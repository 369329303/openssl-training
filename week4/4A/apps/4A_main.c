#include "4A/4A_main.h"

int main() {

  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  BIO *web = NULL, *out = NULL;
  X509 *cert = NULL;

  /* 将 out 与 stdout 绑定在一起 */
  out = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* 创建一个 TLS 连接上下文 */
  if (!(ctx = SSL_CTX_new(TLS_method()))) {
    fprintf(stderr, "ERROR: SSL_CTX_new: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 设置参数 -- 验证服务器证书 */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  /* 设置 CAfile 的路径 */
  if (1 != SSL_CTX_load_verify_locations(ctx, "KoalCARoot.crt", NULL)) {
    fprintf(stderr, "ERROR: SSL_CTX_load_verify: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 客户端证书 */
  if (1 != SSL_CTX_use_certificate_file(ctx, "mypub.pem", SSL_FILETYPE_PEM)) {
    fprintf(stderr, "ERROR: SSL_CTX_use_certificate_file: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  /* 客户端证书对应的私钥 */
  if (1 != SSL_CTX_use_PrivateKey_file(ctx, "mypri.pem", SSL_FILETYPE_PEM)) {
    fprintf(stderr, "ERROR: SSL_CTX_use_PrivateKey_file: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 创建一个用于 TLS 连接的 bio */
  if (!(web = BIO_new_ssl_connect(ctx))) {
    fprintf(stderr, "ERROR: BIO_new_ssl_connect: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 从 bio 流中获取到 tls 信息 */
  BIO_get_ssl(web, &ssl);
  if (!ssl) {
    fprintf(stderr, "ERROR: BIO_get_ssl: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 给 ssl 添加回调函数,用于打印 tls 握手信息 */
  SSL_set_msg_callback(ssl, msg_cb);
  SSL_set_msg_callback_arg(ssl, out);

  /* 设置服务器的地址, 不会出错 */
  BIO_set_conn_hostname(web, "10.0.1.81:443");

  /* 建立 TCP 连接 */
  if (1 != BIO_do_connect(web)) {
    fprintf(stderr, "ERROR: BIO_do_connect: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 建立 TLS 连接 */
  if (1 != BIO_do_handshake(web)) {
    fprintf(stderr, "ERROR: BIO_do_handshake: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 获取对方证书 */
  if (!(cert = SSL_get_peer_certificate(ssl))) {
    fprintf(stderr, "ERROR: SSL_get_peer_certificate: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  } else {
    X509_free(cert);
  }

  /* 验证对方证书 */
  if (X509_V_OK != SSL_get_verify_result(ssl)) {
    fprintf(stderr, "ERROR: SSL_get_verify_result: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 释放内存,关闭文件 */
  BIO_free_all(web);
  SSL_CTX_free(ctx);
  return 0;
}
