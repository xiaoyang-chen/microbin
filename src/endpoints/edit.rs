use crate::args::Args;
use crate::endpoints::create::{expiration_to_timestamp, is_valid_expiration, EXPIRATION_OPTIONS};
use crate::endpoints::errors::ErrorTemplate;
use crate::pasta::PastaFile;
use crate::util::animalnumbers::to_u64;
use crate::util::auth;
use crate::util::db::update;
use crate::util::hashids::to_u64 as hashid_to_u64;
use crate::util::misc::{decrypt, encrypt, encrypt_file, remove_expired};
use crate::{AppState, Pasta, ARGS};
use actix_multipart::Multipart;
use actix_web::error::{ErrorBadRequest, ErrorInternalServerError};
use actix_web::{get, post, web, Error, HttpResponse};
use askama::Template;
use crate::i18n::filters;
use bytes::BytesMut;
use bytesize::ByteSize;
use futures::TryStreamExt;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

#[derive(Template)]
#[template(path = "edit.html", escape = "none")]
struct EditTemplate<'a> {
    pasta: &'a Pasta,
    args: &'a Args,
    path: &'a String,
    status: &'a String,
}

/// 编辑时上传的新文件。先落到临时文件，权限校验通过后再写入附件目录。
struct UploadedEditFile {
    file: PastaFile,
    temp: NamedTempFile,
}

/// 编辑表单提交上来的字段。
///
/// 编辑同时牵涉两项权限，因此表单里可能出现两个密码字段：
/// * `read_password` —— read 权限的密码。`read_access` 为 `password` 时，
///   正文以该密码加密存储，保存新内容时必须用同一个密码重新加密；
/// * `write_password` —— write 权限的密码。`write_access` 为 `password` 时，
///   必须通过它才能写入。
///
/// 另兼容旧的 `password` 字段名（等价于 `read_password`）。
struct EditForm {
    content: String,
    read_password: String,
    write_password: String,
    keep_files: Vec<String>,
    new_files: Vec<UploadedEditFile>,
    manage_files: bool,
    expiration: Option<String>,
    burn_after: Option<u64>,
    extension: Option<String>,
}

impl EditForm {
    fn new() -> Self {
        Self {
            content: String::new(),
            read_password: String::new(),
            write_password: String::new(),
            keep_files: Vec::new(),
            new_files: Vec::new(),
            manage_files: false,
            expiration: None,
            burn_after: None,
            extension: None,
        }
    }
}

/// 解析编辑表单的 multipart 请求体。
async fn parse_edit_form(mut payload: Multipart) -> Result<EditForm, Error> {
    let mut form = EditForm::new();
    let max_parse_size = ARGS
        .max_file_size_encrypted_mb
        .max(ARGS.max_file_size_unencrypted_mb)
        * 1024
        * 1024;

    while let Some(mut field) = payload.try_next().await? {
        let name = match field.name() {
            Some(name) => name.to_string(),
            None => continue,
        };

        if name == "file" {
            if ARGS.no_file_upload {
                continue;
            }

            let path = match field.content_disposition().and_then(|cd| cd.get_filename()) {
                Some("") | None => continue,
                Some(path) => path,
            };

            let mut file = match PastaFile::from_unsanitized(path) {
                Ok(file) => file,
                Err(e) => {
                    log::warn!("Unsafe file name: {e:?}");
                    continue;
                }
            };

            let mut temp = NamedTempFile::new()
                .map_err(|_| ErrorInternalServerError("Failed to create temporary file"))?;
            let mut size = 0usize;
            while let Some(chunk) = field.try_next().await? {
                size += chunk.len();
                if size > max_parse_size {
                    return Err(ErrorBadRequest(crate::i18n::tr(
                        "File exceeded size limit.",
                    )));
                }
                temp.as_file_mut().write_all(&chunk)?;
            }
            temp.as_file_mut().flush()?;

            file.size = ByteSize::b(size as u64);
            form.new_files.push(UploadedEditFile { file, temp });
            continue;
        }

        let mut buf = BytesMut::new();
        while let Some(chunk) = field.try_next().await? {
            buf.extend_from_slice(&chunk);
        }

        let value = String::from_utf8(buf.to_vec())
            .map_err(|_| ErrorBadRequest(crate::i18n::tr("Invalid UTF-8 in content")))?;

        match name.as_str() {
            "content" => form.content = value,
            "read_password" | "password" => form.read_password = value,
            "write_password" => form.write_password = value,
            "keep_file" => form.keep_files.push(value),
            "manage_files" => {
                form.manage_files = matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            }
            "expiration" => form.expiration = Some(value),
            "burn_after" if ARGS.enable_burn_after => {
                form.burn_after = Some(value.trim().parse::<u64>().map_err(|_| {
                    ErrorBadRequest(crate::i18n::tr("Invalid burn after value."))
                })?)
            }
            "syntax_highlight" if ARGS.highlightsyntax => form.extension = Some(value),
            _ => {}
        }
    }

    Ok(form)
}

fn is_valid_syntax(value: &str) -> bool {
    matches!(
        value,
        "none"
            | "auto"
            | "sh"
            | "c"
            | "cpp"
            | "cs"
            | "pas"
            | "erl"
            | "go"
            | "hs"
            | "html"
            | "lua"
            | "lisp"
            | "java"
            | "js"
            | "kt"
            | "py"
            | "php"
            | "r"
            | "rs"
            | "rb"
            | "sc"
            | "swift"
            | "json"
            | "yaml"
            | "xml"
    )
}

fn current_timestamp() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(_) => {
            log::error!("SystemTime before UNIX EPOCH!");
            0
        }
    }
}

fn unique_file_name(name: &str, used_names: &HashSet<String>) -> String {
    if !used_names.contains(name) {
        return name.to_string();
    }

    let path = Path::new(name);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
    let extension = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|ext| format!(".{ext}"))
        .unwrap_or_default();

    let mut counter = 1;
    loop {
        let candidate = format!("{stem}-{counter}{extension}");
        if !used_names.contains(&candidate) {
            return candidate;
        }
        counter += 1;
    }
}

fn stored_file_path(
    pasta: &Pasta,
    file: &PastaFile,
    encrypted: bool,
    is_primary: bool,
) -> PathBuf {
    if encrypted {
        let named = PathBuf::from(format!(
            "{}/attachments/{}/{}.enc",
            ARGS.data_dir,
            pasta.id_as_animals(),
            file.name()
        ));
        if named.exists() || !is_primary {
            named
        } else {
            PathBuf::from(format!(
                "{}/attachments/{}/data.enc",
                ARGS.data_dir,
                pasta.id_as_animals()
            ))
        }
    } else {
        PathBuf::from(format!(
            "{}/attachments/{}/{}",
            ARGS.data_dir,
            pasta.id_as_animals(),
            file.name()
        ))
    }
}

fn apply_file_changes(pasta: &mut Pasta, form: &EditForm) -> Result<(), Error> {
    let encrypted = pasta.read_requires_password();
    let max_file_size_mb = if encrypted {
        ARGS.max_file_size_encrypted_mb
    } else {
        ARGS.max_file_size_unencrypted_mb
    };
    let max_file_size_bytes = max_file_size_mb * 1024 * 1024;

    if form
        .new_files
        .iter()
        .any(|uploaded| uploaded.file.size.as_u64() > max_file_size_bytes as u64)
    {
        return Err(ErrorBadRequest(crate::i18n::tr("File exceeded size limit.")));
    }

    let mut existing_files = Vec::new();
    if let Some(file) = &pasta.file {
        existing_files.push(file.clone());
    }
    if let Some(attachments) = &pasta.attachments {
        existing_files.extend(attachments.iter().cloned());
    }

    let kept_names: HashSet<&str> = form.keep_files.iter().map(String::as_str).collect();
    let mut used_names: HashSet<String> = existing_files
        .iter()
        .map(|file| file.name().to_string())
        .collect();
    let attachment_dir = format!(
        "{}/attachments/{}",
        ARGS.data_dir,
        pasta.id_as_animals()
    );
    fs::create_dir_all(&attachment_dir).map_err(|_| {
        ErrorInternalServerError(crate::i18n::tr("Failed to create attachment directory"))
    })?;

    let mut new_files = Vec::new();
    for uploaded in &form.new_files {
        let name = unique_file_name(uploaded.file.name(), &used_names);
        used_names.insert(name.clone());
        let path = PathBuf::from(format!("{attachment_dir}/{name}"));

        if fs::copy(uploaded.temp.path(), &path).is_err() {
            let _ = fs::remove_file(&path);
            return Err(ErrorInternalServerError("Failed to save uploaded file"));
        }
        if encrypted {
            let path_str = path.to_string_lossy().to_string();
            if encrypt_file(&form.read_password, &path_str).is_err() {
                let _ = fs::remove_file(&path);
                return Err(ErrorInternalServerError("Failed to encrypt file"));
            }
        }

        new_files.push(PastaFile {
            name,
            size: ByteSize::b(uploaded.file.size.as_u64()),
        });
    }

    for (index, file) in existing_files.iter().enumerate() {
        if !kept_names.contains(file.name()) {
            let path = stored_file_path(pasta, file, encrypted, index == 0);
            if path.exists() {
                if let Err(e) = fs::remove_file(&path) {
                    log::warn!("Failed to remove file {}: {}", path.display(), e);
                }
            }
        }
    }

    let mut files: Vec<PastaFile> = existing_files
        .into_iter()
        .filter(|file| kept_names.contains(file.name()))
        .collect();
    files.extend(new_files);
    pasta.file = files.first().cloned();
    pasta.attachments = if files.len() > 1 {
        Some(files[1..].to_vec())
    } else {
        None
    };

    if files.is_empty() {
        let _ = fs::remove_dir(&attachment_dir);
    }

    Ok(())
}

/// 应用一次编辑，返回 `true` 表示已保存。
///
/// 两道校验：
/// 1. **write**：`refuse` 一律拒绝；`password` 必须提供正确的 write 密码。
/// 2. **read**：`password` 时必须提供正确的 read 密码，并用它重新加密正文
///    （正文与附件在存储时就是以 read 密码加密的）。
fn apply_edit(pastas: &mut Vec<Pasta>, index: usize, form: &EditForm) -> Result<bool, Error> {
    if !pastas[index].editable || pastas[index].write_refused() {
        return Ok(false);
    }

    if pastas[index].write_requires_password()
        && !auth::verify_write_password(&pastas[index], &form.write_password)
    {
        return Ok(false);
    }

    let content = if pastas[index].read_requires_password() {
        if !auth::verify_read_password(&pastas[index], &form.read_password) {
            return Ok(false);
        }
        encrypt(&form.content, &form.read_password)
    } else {
        form.content.to_owned()
    };

    let new_expiration = match form.expiration.as_deref() {
        None | Some("") | Some("keep") => None,
        Some(value) => {
            if !EXPIRATION_OPTIONS.contains(&value)
                || !is_valid_expiration(value, &ARGS.max_expiry)
                || (value == "never" && !ARGS.eternal_pasta)
            {
                return Err(ErrorBadRequest(crate::i18n::tr(
                    "Expiration exceeds maximum allowed",
                )));
            }
            Some(expiration_to_timestamp(value, current_timestamp()))
        }
    };

    let new_extension = if ARGS.highlightsyntax {
        match form.extension.as_deref() {
            Some(value) if !is_valid_syntax(value) => {
                return Err(ErrorBadRequest(crate::i18n::tr("Invalid syntax option.")));
            }
            Some(value) => Some(value.to_string()),
            None => None,
        }
    } else {
        None
    };

    if form.manage_files && !ARGS.no_file_upload {
        apply_file_changes(&mut pastas[index], form)?;
    }

    pastas[index].content.replace_range(.., &content);
    if let Some(expiration) = new_expiration {
        pastas[index].expiration = expiration;
    }
    if ARGS.enable_burn_after {
        if let Some(burn_after) = form.burn_after {
            pastas[index].burn_after_reads = burn_after;
        }
    }
    if let Some(extension) = new_extension {
        pastas[index].extension = extension;
    }

    // save pasta in database
    update(Some(&*pastas), Some(&pastas[index]));

    Ok(true)
}

fn redirect_to(location: &str) -> HttpResponse {
    HttpResponse::Found()
        .append_header(("Location", location.to_string()))
        .finish()
}

fn error_page() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

/// 进入编辑页前的统一判定：
/// * 服务端禁止编辑，或该上传的 write 权限为 `refuse` —— 无法编辑，回首页；
/// * read 权限要求密码 —— 先跳到密码页（拿到明文正文才谈得上编辑）；
/// * 否则直接渲染编辑表单。
fn edit_entry(pasta: &Pasta, status: &str) -> HttpResponse {
    if !pasta.editable || pasta.write_refused() {
        return redirect_to(&format!("{}/", ARGS.public_path_as_str()));
    }

    if pasta.read_requires_password() {
        let suffix = if status.is_empty() {
            String::new()
        } else {
            format!("/{}", status)
        };

        return redirect_to(&format!(
            "{}/auth_edit_private/{}{}",
            ARGS.public_path_as_str(),
            pasta.id_as_animals(),
            suffix
        ));
    }

    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(
        EditTemplate {
            pasta,
            args: &ARGS,
            path: &String::from("edit"),
            status: &String::from(status),
        }
        .render()
        .unwrap(),
    )
}

#[get("/edit/{id}")]
pub async fn get_edit(data: web::Data<AppState>, id: web::Path<String>) -> HttpResponse {
    let mut pastas = data.pastas.lock().unwrap();

    let id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id.into_inner()).unwrap_or(0)
    };

    remove_expired(&mut pastas);

    for pasta in pastas.iter() {
        if pasta.id == id {
            return edit_entry(pasta, "");
        }
    }

    error_page()
}

#[get("/edit/{id}/{status}")]
pub async fn get_edit_with_status(
    data: web::Data<AppState>,
    param: web::Path<(String, String)>,
) -> HttpResponse {
    let mut pastas = data.pastas.lock().unwrap();

    let (id, status) = param.into_inner();

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    remove_expired(&mut pastas);

    for pasta in pastas.iter() {
        if pasta.id == intern_id {
            return edit_entry(pasta, &status);
        }
    }

    error_page()
}

/// 密码页提交后的落地处理：校验 read 密码，然后把正文解密后交给编辑器。
///
/// 保存新内容时需要同一个 read 密码重新加密，因此编辑表单里还会再要一次
/// read 密码（模板中按 `pasta.read_requires_password()` 决定是否显示）。
#[post("/edit_private/{id}")]
pub async fn post_edit_private(
    data: web::Data<AppState>,
    id: web::Path<String>,
    payload: Multipart,
) -> Result<HttpResponse, Error> {
    let id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id.into_inner()).unwrap_or(0)
    };

    let password = auth::password_from_multipart(payload).await?;

    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    // remove expired pastas (including this one if needed)
    remove_expired(&mut pastas);

    let index = match pastas.iter().position(|pasta| pasta.id == id) {
        Some(index) => index,
        None => return Ok(error_page()),
    };

    if !pastas[index].can_edit() {
        return Ok(redirect_to(&format!("{}/", ARGS.public_path_as_str())));
    }

    if pastas[index].read_requires_password()
        && !auth::verify_read_password(&pastas[index], &password)
    {
        return Ok(redirect_to(&format!(
            "{}/auth_edit_private/{}/incorrect",
            ARGS.public_path_as_str(),
            pastas[index].id_as_animals()
        )));
    }

    let original_content = pastas[index].content.to_owned();

    // 正文以 read 密码加密，这里临时解密以便在编辑器中显示明文
    if pastas[index].read_requires_password() && !original_content.is_empty() {
        if let Ok(plain) = decrypt(&original_content, &password) {
            pastas[index].content.replace_range(.., plain.as_str());
        }
    }

    // serve pasta in template
    let response = HttpResponse::Ok().content_type("text/html; charset=utf-8").body(
        EditTemplate {
            pasta: &pastas[index],
            args: &ARGS,
            path: &String::from("submit_edit_private"),
            status: &String::from(""),
        }
        .render()
        .unwrap(),
    );

    // 内存里恢复密文，避免明文被后续持久化
    pastas[index].content = original_content;

    Ok(response)
}

#[post("/submit_edit_private/{id}")]
pub async fn post_submit_edit_private(
    data: web::Data<AppState>,
    id: web::Path<String>,
    payload: Multipart,
) -> Result<HttpResponse, Error> {
    let id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id.into_inner()).unwrap_or(0)
    };

    let form = parse_edit_form(payload).await?;

    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    // remove expired pastas (including this one if needed)
    remove_expired(&mut pastas);

    let index = match pastas.iter().position(|pasta| pasta.id == id) {
        Some(index) => index,
        None => return Ok(error_page()),
    };

    if !apply_edit(&mut pastas, index, &form)? {
        return Ok(redirect_to(&format!(
            "{}/edit/{}/incorrect",
            ARGS.public_path_as_str(),
            pastas[index].id_as_animals()
        )));
    }

    Ok(redirect_to(&format!(
        "{}/auth/{}/success",
        ARGS.public_path_as_str(),
        pastas[index].id_as_animals()
    )))
}

#[post("/edit/{id}")]
pub async fn post_edit(
    data: web::Data<AppState>,
    id: web::Path<String>,
    payload: Multipart,
) -> Result<HttpResponse, Error> {
    let id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id.into_inner()).unwrap_or(0)
    };

    let form = parse_edit_form(payload).await?;

    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let index = match pastas.iter().position(|pasta| pasta.id == id) {
        Some(index) => index,
        None => return Ok(error_page()),
    };

    if !apply_edit(&mut pastas, index, &form)? {
        return Ok(redirect_to(&format!(
            "{}/edit/{}/incorrect",
            ARGS.public_path_as_str(),
            pastas[index].id_as_animals()
        )));
    }

    Ok(redirect_to(&format!(
        "{}/uploaded/{}",
        ARGS.public_path_as_str(),
        pastas[index].id_as_animals()
    )))
}
