from os import get_terminal_size, system, getlogin, getcwd, path, environ, makedirs
from re import findall
import subprocess
import re, sys
import time
from io import StringIO
from datetime import datetime, timezone
import configparser
import os

librairies = ["xlsxwriter","colorama", "tqdm", "azure-monitor-query", "azure-identity", "azure.mgmt.network"]

for lib in librairies:
    try:
        __import__(lib)
    except ImportError:
        print(f"La librairie {lib} n'est pas installée. Tentative d'installation...")
        try:
            subprocess.check_call(["pip", "install", lib])
            print(f"{lib} a été installée avec succès !")
        except subprocess.CalledProcessError:
            print(f"Impossible d'installer {lib}. Vérifier que pip est bien configuré.")

### DEPENDANCES AZURE
import azure.monitor.query
from xlsxwriter import Workbook # Pour pouvoir écrire dans un fichier xlsx avec du formattage
from colorama import Fore, Style
from tqdm import tqdm # pour la progress bar
import azure # pour faire la vérification du type
from azure.identity import DefaultAzureCredential # Permet de créer un token pour interroger Azure à partir de la recherche des ids (qu'on doit mettre dans des variables d'environnement)
from azure.monitor.query import LogsQueryClient
from azure.mgmt.network import NetworkManagementClient # Pour récupérer les infos relatives à la config du WAF
from azure.core.exceptions import ClientAuthenticationError
# Variables globales
TYPE_RENDU_EXCEL = 0


LIGHTGREEN = Fore.LIGHTGREEN_EX
LIGHTBLUE = Fore.LIGHTBLUE_EX
LIGHTRED = Fore.LIGHTRED_EX
LIGHTMAGENTA = Fore.LIGHTMAGENTA_EX
LIGHTWHITE = Fore.LIGHTWHITE_EX
LIGHTCYAN = Fore.LIGHTCYAN_EX
LIGHTYELLOW = Fore.LIGHTYELLOW_EX
RED = Fore.RED
GREEN = Fore.GREEN
RESET_ALL = Style.RESET_ALL


# Pour pouvoir récupérer les credentials qui permettent ensuite de faire une requête depuis un client Logs analytics
def init_azure_credentials() -> DefaultAzureCredential:
    try:
        # Pour éviter le message moche de la lib azure on redirige la sortie d'erreur temporairement pour n'afficher que mon message
        # en cas d'exception
        err_buffer = StringIO()
        sys.stderr = err_buffer


        config_azure = configparser.ConfigParser()
        config_azure.read('config.ini')

        # Ensuite on récupère du fichier de config les différents champs
        AZURE_CLIENT_ID = config_azure['AZURE']['AZURE_CLIENT_ID']
        AZURE_TENANT_ID = config_azure['AZURE']['AZURE_TENANT_ID']
        AZURE_CLIENT_SECRET = config_azure['AZURE']['AZURE_CLIENT_SECRET']
        ID_RESSOURCE = config_azure['AZURE']['ID_RESSOURCE']

        # Puis on initialise les variables d'environnement dans lesquelles AzureCredential va chercher (pour créer la connexion et retourner le token)
        environ["AZURE_CLIENT_ID"] = AZURE_CLIENT_ID
        environ["AZURE_TENANT_ID"] = AZURE_TENANT_ID
        environ["AZURE_CLIENT_SECRET"] = AZURE_CLIENT_SECRET
        environ["ID_RESSOURCE"] = ID_RESSOURCE

        # On crée l'objet credential et on le retourne
        credential = DefaultAzureCredential() # Ca va chercher dans l'environnement 
        return credential

    except KeyError as e:
        sys.stderr = sys.__stderr__
        clear_console()
        print_center(get_logo())
        print(LIGHTRED + "Les 4 noms de champs devant être présents dans le fichier config.ini sont respectivement : AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET et ID_RESSOURCE" + RESET_ALL)
    except Exception as e:
        sys.stderr = sys.__stderr__
    finally:
        sys.stderr = sys.__stderr__
    
    


# Permet d'obtenir les infos relatives au WAF (mode, état, etc.)
def get_waf_infos(credential):
    try:
        # Pour éviter le message moche de la lib azure on redirige la sortie d'erreur temporairement pour n'afficher que mon message
        err_buffer = StringIO()
        sys.stderr = err_buffer


        # On commence par récupérer l'id de l'abonnement ainsi que le ressource group auquel appartient le WAF
        id_ressource = environ.get("ID_RESSOURCE")
        # Pour ruser, on peut le récupérer depuis l'URI dans le config.ini qui correspond à l'id de la ressource : 
        nom_rg = re.search(r"resourceGroups/(.*?)/providers", id_ressource).group(1)
        id_sub = re.search(r"/subscriptions/(.*?)/resourceGroups", id_ressource).group(1)
        nom_ag = re.search(r"/applicationGateways/(.*)", id_ressource).group(1)

        # Maintenant on crée un client network qui va nous permettre de récupérer le nom du WAF, et à partir de son nom, sa configuration
        network_client = NetworkManagementClient(credential, id_sub)
        ag = network_client.application_gateways.get(nom_rg, nom_ag)

        # On récupère maintenant le nom du WAF grâce à l'objet Application Gateway qu'on vient de récupérer ci-dessus
        id_waf = getattr(ag.firewall_policy, 'id')
        nom_waf = re.search(r"/ApplicationGatewayWebApplicationFirewallPolicies/(.*)", id_waf).group(1)


        # On récupère directement notre WAF à partir de son nom et son rg
        waf = network_client.web_application_firewall_policies.get(nom_rg, nom_waf)
        environ["WAF_MODE"] = getattr(waf.policy_settings, 'mode')
        environ["WAF_NAME"] = nom_waf
        return waf.policy_settings
    except ClientAuthenticationError as e:
        sys.stderr = sys.__stderr__ # On retablit la sortie par défaut des erreurs
        clear_console()
        print_center(get_logo())
        print_center(LIGHTRED + "Informations remplies dans le config.ini incorrectes. Merci de vérifier !" + RESET_ALL)
        return None
    except Exception as e:  # Pour les autres exceptions
        sys.stderr = sys.__stderr__
        print("Une erreur s'est produite:", str(e)) 
        return None
    finally: # Au cas où quelque chose d'innatendu se produit
        sys.stderr = sys.__stderr__


def get_azure_logs(credential):
    try:

        # On crée notre client pour effectuer les requêtes.
        logs_client = LogsQueryClient(credential)

        # On prépare notre requête
        requete = """
        AzureDiagnostics
        | where OperationName == "ApplicationGatewayFirewall" and action_s == "Matched"
        | summarize count() by ruleId_s, details_data_s
        | order by count_
        """


        # Pour la timzeone c'est UTC par défaut, comme sur Azure
        while True:
            debut = input(LIGHTWHITE + f"{getlogin()} $ Date de début (format AAAA-MM-JJ HH:MM:SS) > " + LIGHTMAGENTA)
            try:
                datetime.strptime(debut, '%Y-%m-%d %H:%M:%S')
                break # Si la conversion a marché on sort de la boucle, sinon on recommence
            except ValueError:
                print(LIGHTRED + "Format de date incorrect...")

        debut = datetime.fromisoformat(debut).replace(tzinfo=timezone.utc)
        debut_utc = debut.astimezone(timezone.utc)


        while True:
            fin = input(LIGHTWHITE + f"{getlogin()} $ Date de fin du timespan (format AAAA-MM-JJ HH:MM:SS) > " + LIGHTMAGENTA)
            try:
                datetime.strptime(fin, '%Y-%m-%d %H:%M:%S')
                break # Si la conversion a marché on sort de la boucle, sinon on recommence
            except ValueError:
                print(LIGHTRED + "Format de date incorrect...")
        
        fin = datetime.fromisoformat(fin).replace(tzinfo=timezone.utc)
        fin_utc = fin.astimezone(timezone.utc)

        timespan = (debut_utc, fin_utc)



        clear_console()
        print_center(get_logo())

        print_center(LIGHTGREEN + "Exécution de la requête aux services Azure.." + RESET_ALL)


        results =  logs_client.query_resource(environ.get("ID_RESSOURCE"), query=requete, timespan=timespan)


        if isinstance(results, azure.monitor.query._models.LogsQueryPartialResult):
            print(LIGHTYELLOW + "\n\nLes donnéees récupérées via une requête sont limitées par Azure. Veuillez réduire l'écart de temps entre le début et la fin..." + RESET_ALL)
            input(LIGHTWHITE + "Appuyez sur une entrée pour revenir au menu..." + RESET_ALL)
            return None
        
        data = []

        for table in results.tables:
            if table.name == 'PrimaryResult':
                for row in table.rows:
                    data.append(row)

        return data

    except Exception as e:
        print("Erreur de connexion à Azure..." + str(e))
        time.sleep(3)
        return None




# Trie le dictionnaire selon le type
def trier_dictionnaire(dictionnaire):

    # On crée une fonction locale juste dans le scope de la fonction trier dictionnaire car on peut l'utiliser.
    # comme ça elle trie les sous dictionnaires et on l'utilise dans la fonction sort du tri du dictionnaire global
    def somme_valeurs(sous_dict) -> int:
        return sum(valeur[1] for valeur in sous_dict.values())

    global TYPE_RENDU_EXCEL
    dict_trie = {} # On doit passer par une variable temporaire on peut pas direct trier le dictionnaire
    match TYPE_RENDU_EXCEL:
        case 1:
            dict_trie = dict(sorted(dictionnaire.items(), key=lambda element: element[1], reverse=True))
        case 2:
            # On trie déjà tous les sous-dictionnaires
            for cle in dictionnaire.keys():
                sous_dict_trie = dict(sorted(dictionnaire[cle].items(), key=lambda element : element[1][1], reverse=True))
                dictionnaire[cle] = sous_dict_trie
            # Maintenant on trie le dictionnaire principal
            dict_trie = dict(sorted(dictionnaire.items(), key=lambda element: somme_valeurs(element[1]), reverse=True))
        case 3:
            for cle in dictionnaire.keys():
                sous_dict_trie = dict(sorted(dictionnaire[cle].items(), key=lambda sous_cle: sous_cle[1], reverse=True))
                dictionnaire[cle] = sous_dict_trie
            # Tri personnalisé pour le dictionnaire en fonction du nombre d'occurrences
            dict_trie = dict(sorted(dictionnaire.items(), key=lambda item: sum(item[1].values()), reverse=True))


    return dict_trie

# méthode globale appelée dans le main pour rendre un excel
def rendre_excel(dictionnaire, worksheet, workbook):
    global TYPE_RENDU_EXCEL

    match TYPE_RENDU_EXCEL:
        case 1:
            worksheet.set_column(0, 0, width=40)
            rendre_excel_type_un(dictionnaire, worksheet, workbook)
        case 2:
            worksheet.set_column(0, 0, width=20)
            worksheet.set_column(1, 1, width=50)
            format = workbook.add_format({'text_wrap': True})
            worksheet.set_row(0, None, format)
            rendre_excel_type_deux(dictionnaire, worksheet, workbook, format)
        case 3:
            worksheet.set_column(0, 0, width=35)
            worksheet.set_column(1, 1, width=20)
            worksheet.set_column(2, 2, width=30)
            format = workbook.add_format({'text_wrap': True})
            worksheet.set_row(0, None, format)
            rendre_excel_type_trois(dictionnaire, worksheet, workbook, format)
        


def rendre_excel_type_un(dictionnaire, worksheet, workbook):
    bold = workbook.add_format({'bold': True})
    worksheet.write(0, 0, "Nom du champ", bold)
    worksheet.write(0, 1, "Type du champ", bold)
    worksheet.write(0, 2, "Occurences", bold)
    indice = 1
    for cle in dictionnaire.keys():
        # cle = param, donc on va la split selon le : 
        # donc indice 0 y a nom_param et indice 1 type_param
        n_t_param = cle.split(':')
        worksheet.write(indice, 0, str(n_t_param[0]))
        worksheet.write(indice, 1, str(n_t_param[1]))
        worksheet.write(indice, 2, dictionnaire[cle])
        indice += 1


def rendre_excel_type_deux(dictionnaire, worksheet, workbook, format) -> None:
    bold = workbook.add_format({'bold': True})
    worksheet.write(0, 0, "Identifiant de la règle", bold)
    worksheet.write(0, 1, "Champ : [TYPE, COMPTE]", bold)


    # On essaye de trier le dictionnaire : 
    # dict_trie = sorted(dictionnaire, key=lambda element : element[1])
    indice = 1
    for cle in dictionnaire.keys():
        worksheet.write(indice, 0, str(cle))
        champ_principal = ""

        for sous_cle in dictionnaire[cle].keys():

            # print(f'fer : {indice}' + sous_cle)
            champ = str(sous_cle) + ' : {'
            for item in dictionnaire[cle][sous_cle]:
                champ += str(item) + ', '
            champ = champ[:-2]
            champ += '},'
            champ_principal += champ + "\n"
        champ_principal = champ_principal[:-2]
        worksheet.write(indice, 1, champ_principal, format)
        indice += 1


def rendre_excel_type_trois(dictionnaire, worksheet, workbook, format) -> None:
    bold = workbook.add_format({'bold': True})
    worksheet.write(0, 0, "Nom du champ", bold)
    worksheet.write(0, 1, "Type du champ", bold)
    worksheet.write(0, 2, "Règles associées + nb occurences", bold)
    indice = 1
    for cle in dictionnaire.keys():
        # Donc là on va écrire le champ + son type
        param_complet = cle.split(':')
        worksheet.write(indice, 0, str(param_complet[0]))
        worksheet.write(indice, 1, str(param_complet[1]))
        champ_principal = " {\n"
        champ = ""
        for sous_cle in dictionnaire[cle].keys():
            champ += str(sous_cle) + " -> " + str(dictionnaire[cle][sous_cle]) + ',\n'
        champ = champ[:-2]
        champ_principal += champ + "\n }"
        worksheet.write(indice, 2, champ_principal, format)
        indice += 1
            
            
            

def remplir_dictionnaire(dictionnaire, id_regle, nom_param, type_param, nb_occurences):
    global TYPE_RENDU_EXCEL
            
    # S'il y a un ou plusieurs espaces dans nom_param, c'est qu'on est tombé sur un filter, et qu'y a plusieurs paramètres
    liste_param_vide = nom_param.split(' ')
    liste_param = [element for element in liste_param_vide if element]

    match TYPE_RENDU_EXCEL:
        case 1:
            # Pour stocker simplement param et type de param
            # on va utiliser : pour séparer puis split au moment d'écrire l'excel, comme ça si un champ
            # est disponible en ARGS et en COOKIE, les deux seront mis à part
            # en mode example : feur:COOKIE et on peut en même temps avoir feur:ARGS
            # et les deux apparaissent dans l'excel comme ça 
            for param in liste_param: 
                param_final = param + ":" + type_param
                if param_final not in dictionnaire:
                    dictionnaire[param_final] = nb_occurences
                else:
                    dictionnaire[param_final] += nb_occurences    
            
        case 2:
             # On vérifie si le dictionnaire contient déjà la clé en entrée, sinon, on la rajoute
            # S'il y a un ou plusieurs espaces dans nom_param, c'est qu'on est tombé sur un filter, et qu'y a plusieurs paramètres
            # count += nb_occurences
            # print("LISTE PARAM : " + str(liste_param))
            if id_regle not in dictionnaire:

                    dictionnaire[id_regle] = {} # On initialise déjà à vide pour après parcourir les champs
                    for param in liste_param:
                        dictionnaire[id_regle][param] = [type_param, nb_occurences]
                # Si la règle n'est pas encore en tant que clé, alors on va instancier le ligne
            else: # Dans le cas où la règle est déjà répertoriée    
                # Puis on s'occupe de vérifier maintenant si la ligne problématique a déjà été répertorié dans le dictionnaire
                for param in liste_param:
                    if param in dictionnaire.get(id_regle).keys() :
                        dictionnaire.get(id_regle).get(param)[1] += nb_occurences
                    else: # cas où la règle existe mais pas ce param en question
                        dictionnaire[id_regle][param] = [type_param, nb_occurences]
        case 3:
            for param in liste_param:
                param_final = param + ":" + type_param
                if param_final not in dictionnaire:
                    dictionnaire[param_final] = {
                            id_regle : nb_occurences
                        }
                else:
                    if id_regle in dictionnaire[param_final].keys():
                        dictionnaire[param_final][id_regle] += nb_occurences
                    else:
                        dictionnaire[param_final][id_regle] = nb_occurences
        case _:
            pass


# On passe une chaine en paramètre, et ça print au milieu
def print_center(chaine:str) -> None:
    print(chaine.center(get_terminal_size().columns))

# Pour effacer tout ce qu'il y a dans la console
def clear_console() -> None:
    try:
        system("cls")
    except:
        system("clear")


def quitter_programme() -> None:
    symbols = ['⣾', '⣷', '⣯', '⣟', '⡿', '⢿', '⣻', '⣽']
    i = 0
    j = 0
    print(LIGHTBLUE)
    while j < 30:
        i = (i + 1) % len(symbols)
        
        print('\r\033[K  %s Fermeture en cours...' % symbols[i], flush=True, end='')
        time.sleep(0.1)
        j += 1
    clear_console()
    print_center(get_logo())
    print(GREEN + "Merci d'avoir utilisé le programme.." + RESET_ALL)
    exit(0)

# Permet d'afficher le logo du programme dès qu'on appelle la fonction
def get_logo():
    return f"""{LIGHTBLUE}

            $$$$$$\                       $$\                                     $$\      $$\  $$$$$$\  $$$$$$$$\ 
            $$  __$$\                     $$ |                                    $$ | $\  $$ |$$  __$$\ $$  _____|
            $$ /  $$ |$$$$$$$\   $$$$$$\  $$ |$$\   $$\  $$$$$$$\  $$$$$$\        $$ |$$$\ $$ |$$ /  $$ |$$ |      
            $$$$$$$$ |$$  __$$\  \____$$\ $$ |$$ |  $$ |$$  _____|$$  __$$\       $$ $$ $$\$$ |$$$$$$$$ |$$$$$\    
            $$  __$$ |$$ |  $$ | $$$$$$$ |$$ |$$ |  $$ |\$$$$$$\  $$$$$$$$ |      $$$$  _$$$$ |$$  __$$ |$$  __|   
            $$ |  $$ |$$ |  $$ |$$  __$$ |$$ |$$ |  $$ | \____$$\ $$   ____|      $$$  / \$$$ |$$ |  $$ |$$ |      
            $$ |  $$ |$$ |  $$ |\$$$$$$$ |$$ |\$$$$$$$ |$$$$$$$  |\$$$$$$$\       $$  /   \$$ |$$ |  $$ |$$ |      
            \__|  \__|\__|  \__| \_______|\__| \____$$ |\_______/  \_______|      \__/     \__|\__|  \__|\__|      
                                              $$\   $$ |                                                           
                                              \$$$$$$  |     {LIGHTRED}Stanislas TROHA{LIGHTBLUE}                       
                                               \______/                                             

                                                {RESET_ALL}"""


def main():

    global TYPE_RENDU_EXCEL
    
    system('mode con: cols=125 lines=40')

    # On vérifie déjà au début si les infos dans config.ini sont correctes en essayant de créer l'objet : 
    credential = init_azure_credentials()
    if not credential:
        return
    
    proprietes_waf = get_waf_infos(credential)
    if not proprietes_waf:
        return


    # Sinon, c'est que les infos étaient correctes et ça a fonctionné
    while True:
        print_center(get_logo())

        print_center(f"{LIGHTCYAN}Informations du WAF {LIGHTGREEN}{environ.get('WAF_NAME')}")
        print_center(f"{LIGHTCYAN}Mode : {LIGHTGREEN}{environ.get('WAF_MODE')}")
        print_center(f"{LIGHTCYAN}Etat : {LIGHTGREEN}{getattr(proprietes_waf, 'state')}")
        print_center(f"{LIGHTCYAN}Vérification du corps de la requête : {LIGHTGREEN}{getattr(proprietes_waf, 'request_body_check')}")
        print_center(f"{LIGHTCYAN}Taille maximale du corps de la requête : {LIGHTGREEN}{getattr(proprietes_waf, 'max_request_body_size_in_kb')} Ko")
        print_center(f"{LIGHTCYAN}Rejette si corps trop gros (effectif en mode prévention) : {LIGHTGREEN}{getattr(proprietes_waf, 'request_body_enforcement')}")
        print_center(f"{LIGHTCYAN}Autoriser l'upload de fichier : {LIGHTGREEN}{getattr(proprietes_waf, 'file_upload_limit_in_mb')} Mo")
        print_center(f"{LIGHTCYAN}Rejeter les requêtes si trop gros fichier : {LIGHTGREEN}{getattr(proprietes_waf, 'file_upload_enforcement')}\n\n")
       
        print_center(LIGHTBLUE + "-----------------------------------------------------------------------------------------------\n\n")

        print(f"{LIGHTMAGENTA}[1] Arguments les plus présents") # Arguments les plus présents + count()
        print("[2] Liste des arguments pour chaque règle déclenchée") # Ordered by id_regle, avec dictionnaire des arguments et leur count()
        print("[3] Liste des règles déclenchées avec count pour chaque argument")
        print("[4] Quitter l'application\n")
        while(True):
            x = str(input(LIGHTWHITE + f"{getlogin()} $ Choisir une option > " + LIGHTMAGENTA))
            match x:
                case '1':
                    TYPE_RENDU_EXCEL = int(x)
                    break
                case '2':
                    TYPE_RENDU_EXCEL = int(x)
                    break
                case '3':
                    TYPE_RENDU_EXCEL = int(x)
                    break
                case '4':
                    quitter_programme()
                case '':
                    pass
                case _:
                    print(f"{RED}OPTION INVALIDE...{RESET_ALL}")
                    pass

        # On va créer le dictionnaire qui contient les entrées, on écrira les résultats dans un excel après...
        dictionnaire = dict()

        # On récupère les données d'Azure
        logs = get_azure_logs(credential)

        if logs is None: # Si les logs sont nuls, il y a peut être eu un problème avec la requête donc on recommence
            clear_console()
            continue  # Recommence le while principal

        try:

            lignes = logs

            print_center(f"{LIGHTRED}Récupération des champs en cours{RESET_ALL}\n\n\n")
            
            # Puis on parcourt la liste de logs jusqu'au dernier enregistrement
            for i in tqdm(range(0, len(lignes))):

                # On vérifie en premier lieu s'il y a des caractères mal encodés (oui c'est le cas à 99,99999%)
                try:
                    lignes[i]['details_data_s'].encode('ascii')
                except UnicodeEncodeError:
                    # Si des caractères mal encodés sont détectés, on passe à l'itération suivante
                    continue

                # On récupère les deux champs faciles, règle et count
                id_regle = int(lignes[i]['ruleId_s']) # On convertit en int
                count = lignes[i]['count_']
                nb_occurences = int(count)

                # Les requêtes avec du XML sont infiniement longues, donc ne pas les vérifier avec ma grosse regex
                # Donc petit regex pour trouver les champs interéssants pour remplir le dictionnaire, et une fois ça fait
                # on le remplit directement et on fait pas le reste du code de l'itération
                # Okay, toujours le même pattern si on veut vérifier ça : found within [XML comme ça on parcourt pas les gigantesques lignes
                # qui correspondent au XML, on a juste à garder le count, le type de param, qui est lui même XML
                if "found within [XML:" in lignes[i]['details_data_s']:
                    match = re.search(r'\[XML:(.*?):', lignes[i]['details_data_s'])
                    if match:
                        nom_param = match.group(1)
                        type_param = "XML"
                        remplir_dictionnaire(dictionnaire, id_regle, match.group(1), "XML", nb_occurences)
                    continue


                # Maintenant on crée notre reg ex qui prend un truc du style [ARGUMENT:nom_argument:valeur_argument]
                # regex = re.compile('\[[A-Z_]+\:.*\:.*\]') il faut en trouver une plus puissante qui prend tous les cas
                regex = r'\[([A-Z_]+):([^\[\]]*?(?:\[[^\[\]]*?\])*[^\[\]]*)\]'

                res_expr = findall(regex, lignes[i]['details_data_s'])

                # Si on a trouvé quelque chose via la regex
                if res_expr:

                    expr = res_expr[0][0] # On prend le premier élément du tuple qui est contenu dans l'indice 0 du tableau.

                    # Avec findall, on récupère un tuple qui contient tous les groupes de la regex
                    # donc on reconstruit ce qu'on extrait en mettant ensemble les éléments du tuples
                    for m in range(1, len(res_expr[0])):
                        expr += ':' + res_expr[0][m]


                    type_param = expr.split(':')[0].strip('[') # On extrait le ARGS ou REQUEST_COOKIE par exemple

                    if expr.split(':')[1] == 'filter':
                        # Ici on doit garder tous les arguments dans un tableau qui correspondent aux args filtrés par la règle
                        # dans nom_param
                        # Maintenant, on va ré utiliser une expression régulière pour récupérer les champs qui nous intéressent.
                        pattern = r'(\w+\s(ge|eq|and))'
                        f = findall(pattern, expr)
                        nom_param = ""
                        for j in range(len(f)):
                            nom_param += ' ' + f[j][0].split(' ')[0]
                    else:
                        nom_param = expr.split(':')[1]

                    
                    # ############################################################
                    # Maintenant, tout dépend du case dans lequel on est (1, 2, 3)
                    # ############################################################
                    
                    # Donc on donne ça à une fonction pour pas salir le code inutilement
                    remplir_dictionnaire(dictionnaire, id_regle, nom_param, type_param, nb_occurences)
                        
            clear_console()

            print_center(get_logo())

            # On doit maintenant s'occuper, après le parcours des logs fini, de tout réécrire dans un nouveau document excel
            print_center(LIGHTGREEN + "Parcours du fichier réussi ! Où souhaitez-vous sauvegarder vos données ?\n\n")
            chemin_res = input(LIGHTWHITE + f"{getlogin()} $ Chemin du fichier de résultats {LIGHTYELLOW}SANS L'EXTENSION{LIGHTWHITE} ! > " + LIGHTMAGENTA)
            
            # On vérifie déjà si le dossier existe (l'utilisateur peut l'avoir supprimé pour x raisons)
            # et s'il n'existe pas, alors on le crée 
            chemin_dossier = getcwd() + "/../results"
            if not path.exists(chemin_dossier):
                makedirs(chemin_dossier)

            if not chemin_res[0] == '/':
                chemin_res = '/../results/' + chemin_res
            chemin_res += ".xlsx"
            nom_output = getcwd() + chemin_res
            
            # On crée notre workbook et feuille excel...
            workbook_excel = Workbook(nom_output)
            feuille = workbook_excel.add_worksheet()

            dict_trie = trier_dictionnaire(dictionnaire)
            
            rendre_excel(dict_trie, feuille, workbook_excel)

            # On ferme le fichier d'écriture
            workbook_excel.close()

            clear_console()

            print_center(get_logo())

            print_center(GREEN + f"\n\nEcriture du fichier faite avec succès dans : \n{LIGHTRED}{path.abspath(nom_output)} {LIGHTGREEN}!\n\n")
            
            
            print(f"{LIGHTCYAN}[1] Revenir au menu")
            print("[2] Quitter l'analyseur de logs\n")
            while True:
                opt = str(input(f"{LIGHTWHITE}{getlogin()} $ Choisir une option > {LIGHTMAGENTA}"))
                match opt:
                    case '1':
                        clear_console()
                        break
                    case '2':
                        quitter_programme()
                    case '': # entrée classique
                        pass                        
                    case _: # option invalide
                        print(RED + 'option invalide, veuilez rééssayer' + RESET_ALL)
        except azure.core.exceptions.ClientAuthenticationError as e:
            with open('chained.txt', 'a') as f:
                f.write(str(e) + '\n')
                f.write(str(type(e)))
        except Exception as e:
            with open('error_log_maininin.txt', 'a') as f:
                f.write(str(e) + '\n')
                f.write(str(type(e)))

# Pour lancer le main
if __name__ == "__main__":
    main()