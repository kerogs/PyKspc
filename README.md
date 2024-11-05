## How to use
```sh
py ./auto-install.py
```

### see version
```sh
pykspc -v
```

### see help
```sh
pykspc -h
```

### example (cli)

#### Encrypt
```sh
pykspc encrypt "./file.txt" 91b62c5e9f438fa18d03e8d486f37c5f746098c2fd9854c74f85b65ec6f71ae9 -k
```
#### Decrypt
```sh
pykspc decrypt "./file.txt" 91b62c5e9f438fa18d03e8d486f37c5f746098c2fd9854c74f85b65ec6f71ae9 -k
```

#### Genkey
```
pykspc genkey
```

#### Help
```sh
pykspc -h
```

### example (with php)
```php
<?php

const PYKSPC_KEY = "91b62c5e9f438fa18d03e8d486f37c5f746098c2fd9854c74f85b65ec6f71ae9"; 
$command = 'pykspc ".\main.py" "./test.ksp" '.PYKSPC_KEY.' -e -k -Mi -b';

$output = [];
$return_var = 0;
exec($command, $output, $return_var);


if ($return_var == true) {
    echo "file crypted";
} else {
    echo "Il y a eu une erreur lors de l'exécution de la commande.";
    echo "\nDétails de l'erreur : " . implode("\n", $output);
}

?>
```