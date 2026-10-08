import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

ATTACK_MAP = {
    "normal": "normal",
    "neptune": "dos", "smurf": "dos", "back": "dos", "teardrop": "dos", "pod": "dos",
    "land": "dos", "apache2": "dos", "udpstorm": "dos", "processtable": "dos", "mailbomb": "dos",
    "satan": "probe", "ipsweep": "probe", "nmap": "probe", "portsweep": "probe",
    "mscan": "probe", "saint": "probe",
    "guess_passwd": "r2l", "ftp_write": "r2l", "imap": "r2l", "phf": "r2l",
    "multihop": "r2l", "warezmaster": "r2l", "warezclient": "r2l", "spy": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "snmpguess": "r2l", "snmpgetattack": "r2l",
    "httptunnel": "r2l", "sendmail": "r2l", "named": "r2l", "worm": "r2l",
    "buffer_overflow": "u2r", "loadmodule": "u2r", "rootkit": "u2r", "perl": "u2r",
    "sqlattack": "u2r", "xterm": "u2r", "ps": "u2r",
}

def load_dataset(path):
    df = pd.read_csv(path, names=COLUMNS)
    df = df.drop(columns=["difficulty"])
    df["attack_family"] = df["label"].map(ATTACK_MAP).fillna("autre")
    return df

def prepare(train_path, test_path, held_out_families=None):
    held_out_families = held_out_families or []

    df_train = load_dataset(train_path)
    df_test = load_dataset(test_path)

    df_zeroday_eval = df_test[df_test["attack_family"].isin(held_out_families)].copy()
    df_train = df_train[~df_train["attack_family"].isin(held_out_families)]
    df_test = df_test[~df_test["attack_family"].isin(held_out_families)]

    cat_cols = ["protocol_type", "service", "flag"]
    encoders = {}
    full = pd.concat([df_train[cat_cols], df_test[cat_cols], df_zeroday_eval[cat_cols]])
    for col in cat_cols:
        le = LabelEncoder()
        le.fit(full[col])
        encoders[col] = le
        df_train[col] = le.transform(df_train[col])
        df_test[col] = le.transform(df_test[col])
        if len(df_zeroday_eval):
            df_zeroday_eval[col] = le.transform(df_zeroday_eval[col])

    feature_cols = [c for c in COLUMNS if c not in ("label", "difficulty")]

    scaler = StandardScaler()
    X_train = scaler.fit_transform(df_train[feature_cols])
    X_test = scaler.transform(df_test[feature_cols])
    X_zeroday = scaler.transform(df_zeroday_eval[feature_cols]) if len(df_zeroday_eval) else None

    return {
        "X_train": X_train, "df_train": df_train,
        "X_test": X_test, "df_test": df_test,
        "X_zeroday": X_zeroday, "df_zeroday": df_zeroday_eval,
        "feature_cols": feature_cols, "scaler": scaler, "encoders": encoders,
    }
   
if __name__ == "__main__":

    HELD_OUT_FAMILIES = ["dos"]

    data = prepare(
        train_path="data/KDDTrain.txt",
        test_path="data/KDDTest.txt",  
        held_out_families=HELD_OUT_FAMILIES
    )

    print("Train :", data["X_train"].shape)
    print("Test :", data["X_test"].shape)
    print("Zero-Day :", data["X_zeroday"].shape)
    print("\nFamille utilisée comme Zero-Day :")
    print(data["df_zeroday"]["attack_family"].value_counts())
