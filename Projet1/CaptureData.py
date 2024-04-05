import pyshark
from datetime import datetime, timedelta
from collections import defaultdict

#Chemin vers le fichier pcapng
pcapng_file = '/Users/gg/Documents/Network-Projects/Projet 1/Mathis/Captures/ImportFolder.pcapng'

#Fonction pour calculer le volume de données par minute pour chaque fonctionnalité
def calculate_data_volume(file_path):
    #Dictionnaire pour stocker le volume de données par minute pour chaque fonctionnalité
    data_volume = defaultdict(int)

    #Lecture du fichier pcapng
    capture = pyshark.FileCapture(file_path)

    #Initialisation des variables
    start_time = None
    last_minute = None
    total_bytes = 0

    # Parcours des paquets
    for pkt in capture:
        #Conversion du temps de capture en objet datetime
        capture_time = pkt.sniff_time

        #Initialisation du temps de départ et de la dernière minute
        if start_time is None:
            start_time = capture_time
            last_minute = start_time

        #Si le temps de capture est toujours dans la même minute
        if capture_time - last_minute <= timedelta(minutes=1):
            total_bytes += int(pkt.length)
        else:
            #Calcul du volume de données pour la minute précédente
            data_volume[last_minute] += total_bytes
            #Réinitialisation des variables pour la nouvelle minute
            last_minute = capture_time
            total_bytes = int(pkt.length)

    #Fermeture de la capture
    capture.close()

    return data_volume

# Appel de la fonction pour calculer le volume de données par minute
data_volume = calculate_data_volume(pcapng_file)

# Calcul du nombre total de minutes
total_minutes = len(data_volume)

average_volume_per_minute = sum(data_volume.values()) / total_minutes / 1000000

print(f"Volume moyen de données échangées par minute: {average_volume_per_minute:.2f} Mo")