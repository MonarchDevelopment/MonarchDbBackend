struct db_config {
    String user_name;
    String password;
    String url;
    String db_name;
};

struct config {
    String server_bind;
    String jwt_secret;
    uint32 server_port;
    db_config db_conf;
};

