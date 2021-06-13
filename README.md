# Packer

> Auteur : Flammrock
> License  MIT

### Prérequis

Pour compiler ce projet, vous devez avoir un compilateur capable de compiler du C et d'installer https://github.com/madler/zlib et https://github.com/akheron/jansson

### Compilation

Pour compiler, vous pouvez soit directement utiliser `build.bat` ou exécuter cette ligne de commande :

```bash
gcc -Os -fdata-sections -O3 -ffunction-sections -fipa-pta main.c -lm -lzlibstatic -ljansson -o Packer.exe -D_WIN32 -Wl,--gc-sections -Wl,-O1 -Wl,--as-needed -Wl,--strip-all
```

### Usage

Voici la liste des principales commandes :
- `Packer unpack {OPTIONS}`
- `Packer pack {OPTIONS}`
- `Packer buildtrb {OPTIONS}`
- `Packer signature {OPTIONS}` (à faire)
- `Packer gzip {OPTIONS}` (à faire)
- `Packer unpack {OPTIONS}` (à faire)

L'aide peut s'obtenir en indiquant aucun argument ou en spécifiant `--help` comme ceci :
- `Packer --help`

Voici l'aide produite :
```        Packer unpack {OPTIONS}

                -i, --input=VALUE        Le fichier pack (nsb, scb, trb, ...).
                -o, --output=VALUE       Le fichier de sortie (sous format JSON).
                -p, --prettify           Beautifie le JSON.
                -m, --minify             Minifie le JSON.
                -s, --stdout             Affichage sur la console.
                -s, --verbose            Afficher toutes les informations.


        Packer pack {OPTIONS}

                -i, --input=VALUE        Le fichier JSON.
                -o, --output=VALUE       Le fichier de sortie.
                -p, --prettify           Beautifie le JSON.
                -m, --minify             Minifie le JSON.
                -s, --stdout             Affichage sur la console.
                -s, --verbose            Afficher toutes les informations.


        Packer buildtrb {OPTIONS}

                --scb=VALUE              Le fichier pack SCB ou le fichier unpack SCB.txt.
                --nsb=VALUE              Le fichier pack NSB ou le fichier unpack NSB.txt.
                -o, --output=VALUE       Le fichier de sortie TRB.txt.
                -p, --prettify           Beautifie le JSON.
                -m, --minify             Minifie le JSON.
                -s, --stdout             Affichage sur la console.
                -s, --verbose            Afficher toutes les informations.


        Packer signature {OPTIONS}

                -i, --input=VALUE        Le fichier pack (nsb, scb, ...) ou le fichier unpack (nsb.txt, scb.txt, ...).
                -o, --output=VALUE       Le fichier de sortie qui contiendra la signature (SHA1).
                -s, --stdout             Affichage sur la console.
                -s, --verbose            Afficher toutes les informations.


        Packer gzip {OPTIONS}

                -i, --input=VALUE        Le fichier unpack.
                -o, --output=VALUE       Le fichier de sortie au format gzip (pack).
                -l, --level=VALUE        Le niveau de compression entre 1 et 9.
                -t, --timestamp=VALUE    La date qui sera mis dans le header du fichier gzip.
                -s, --stdout             Affichage sur la console.
                -s, --verbose            Afficher toutes les informations.


        Packer ungzip {OPTIONS}

                -i, --input=VALUE        Le fichier au format gzip (pack).
                -o, --output=VALUE       Le fichier de sortie unpack.
                -s, --stdout             Affichage sur la console.
                -s, --verbose            Afficher toutes les informations.```

### License

Ce projet est sous [licence MIT](https://github.com/git/git-scm.com/blob/main/MIT-LICENSE.txt)
