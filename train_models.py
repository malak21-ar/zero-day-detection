#AUTONCODEUR

from sklearn.neural_network import MLPRegressor   #on importe le modele necessaire pour entrainer l'autoncodeur
import joblib

from preprocess import prepare
data = prepare(   #on charge les donne preparer
    train_path="data/KDDTrain.txt",
    test_path="data/KDDTest.txt",
    held_out_families=["dos"]
)

X_normal = data["X_train"][  #Prendre uniquement le trafic normal
    data["df_train"]["attack_family"] == "normal"
]

autoencoder = MLPRegressor(  #on créer l'Autoencoder
    hidden_layer_sizes=(32, 16, 32),
    activation="relu",
    solver="adam",
    max_iter=100,
    random_state=42
)
autoencoder.fit(X_normal, X_normal) #ici on entraine l'autoncodeur a reconstruire le trafic normal
joblib.dump(autoencoder, "autoencoder.pkl")  #ici on sauvegarde le modele entrainer pour l'utiliser plus tard


#RANDOM FOREST

from sklearn.ensemble import RandomForestClassifier  #importe le modele necessaire pour entrainer le Random Forest
y_train = data["df_train"]["attack_family"] #Préparer les labels

rf = RandomForestClassifier( #on cree le Random Forest
    n_estimators=100,
    random_state=42
)
rf.fit(data["X_train"], y_train) #on entraine le Random Forest a reconnaitre les familles des attques
joblib.dump(rf, "random_forest.pkl") #on sauvegarde le modele entr
