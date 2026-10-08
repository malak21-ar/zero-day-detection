import joblib
import numpy as np
from preprocess import prepare

#on charge les modeles entrainer pour les utiliser dans l'archi hybride
autoencoder = joblib.load("autoencoder.pkl")
random_forest = joblib.load("random_forest.pkl")

#on charge les donnees
data = prepare(
    train_path="data/KDDTrain.txt",
    test_path="data/KDDTest.txt",
    held_out_families=["dos"]
)

#la partie qui va déterminer le seuil de l'Autoencoder
X_normal = data["X_train"][  #on recupere les donnees de trafic normal
    data["df_train"]["attack_family"] == "normal"
]
X_normal_reconstructed = autoencoder.predict(X_normal) #on les reconstruit
normal_error = np.mean( #calcule d'erreur
    (X_normal - X_normal_reconstructed) ** 2,
    axis=1
)
threshold = np.percentile(normal_error, 95)  #difinition du seuil de detection a 95% des erreurs de reconstruction

print("Seuil de détection :", threshold)

X_test_reconstructed = autoencoder.predict(data["X_test"])

test_error = np.mean(  #Faire passer le trafic dans l'Autoencoder
    (data["X_test"] - X_test_reconstructed) ** 2,
    axis=1
)


#la logique hybride 
from collections import Counter


decisions_test = []
for i in range(len(data["X_test"])):
    if test_error[i] > threshold:
        x = data["X_test"][i].reshape(1, -1)
        proba = random_forest.predict_proba(x)[0]
        pred_class = random_forest.classes_[np.argmax(proba)]
        confidence = np.max(proba)

        if pred_class != "normal" and confidence >= 0.6:
            decision = pred_class          # attaque connue, reconnue avec confiance
        else:
            decision = "ZERO-DAY"          # anormal mais non reconnu 
    else:
        decision = "normal"                # pas anormal 

    decisions_test.append(decision)

print("\n JEU DE TEST NORMAL ")
print("Total lignes testées :", len(decisions_test))   #Combien de lignes de trafic au total le pipeline a analysées dans le jeu de test
print("\nRépartition des décisions :", Counter(decisions_test))  #c'est la liste de ce que le PIPELINE A RÉPONDU pour chaque ligne
print("\nPour comparaison, vraies étiquettes réelles :" , Counter(data["df_test"]["attack_family"]))   #ce que chaque ligne était VRAIMENT (l'étiquette d'origine du dataset, attack_family), pas ce que le modèle a deviné.


#test du zero day (famille mise de côté : dos)
X_zeroday_reconstructed = autoencoder.predict(data["X_zeroday"])
zeroday_error = np.mean(
    (data["X_zeroday"] - X_zeroday_reconstructed) ** 2,
    axis=1
)

decisions_zeroday = [
    "ZERO-DAY" if err > threshold else "NORMAL"
    for err in zeroday_error
]

n_total = len(decisions_zeroday)
n_detected = decisions_zeroday.count("ZERO-DAY")

print("\n ZERO-DAY SIMULÉ (famille DoS)")
print("Total lignes testées :", n_total)
print(f"Détectées comme ZERO-DAY : {n_detected} ({100*n_detected/n_total:.1f}%)")
print(f"Ratées (classées normales) : {n_total - n_detected} ({100*(n_total-n_detected)/n_total:.1f}%)")



#test sur une attaque CONNUE (probe) 
print("\n=== TEST SUR UNE ATTAQUE CONNUE (probe) ===")

indices_probe = [
    i for i in range(len(data["df_test"]))
    if data["df_test"]["attack_family"].iloc[i] == "probe"
]

decisions_probe = [decisions_test[i] for i in indices_probe]

print("Total lignes 'probe' dans le test :", len(indices_probe))
print("Répartition des décisions sur ces lignes :", Counter(decisions_probe))

n_correct = decisions_probe.count("probe")
print(f"Correctement identifiées comme 'probe' : {n_correct} ({100*n_correct/len(indices_probe):.1f}%)")
