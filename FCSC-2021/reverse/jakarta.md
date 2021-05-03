# Jakarta

## Énoncé

**50 \| reverse \| Android**

Voici une application Android qui permet de vérifier si le flag est correct.

SHA256\(`Jakarta.apk`\) = `0691a1401bd10c7c2d8cd196f86f8aa23acf707a98aae480a07ec5e1951a1d04`.

## Analyse & Résolution

#### Jadx et analyse du code source

Pour comprendre le fonctionnement de cette application Android j'ai décompilé le fichier `jakarta.apk` vers du code java grâce au décompileur gui [Jadx](https://github.com/skylot/jadx).

```text
$ sudo apt update
$ sudo apt install jadx
```

Partie intéressante de l'arborescence de l'application :

```text
Source Code
└── com
    └── fcsc2021.jakarta
        ├── BuildConfig
        ├── Check
        ├── MainActivity
        └── R
```

Code de la class `MainActivity` :

```java
package com.fcsc2021.jakarta;

import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    /* access modifiers changed from: protected */
    @Override // androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ((Button) findViewById(R.id.button)).setOnClickListener(new View.OnClickListener() {
            /* class com.fcsc2021.jakarta.MainActivity.AnonymousClass1 */

            public void onClick(View v) {
                String candidate = ((TextView) MainActivity.this.findViewById(R.id.flag_input)).getText().toString();
                TextView tv2 = (TextView) MainActivity.this.findViewById(R.id.result_text);
                if (new Check(candidate).valid()) {
                    tv2.setText("Correct!!");
                } else {
                    tv2.setText("Nope.");
                }
            }
        });
        ((TextView) findViewById(R.id.flag_input)).addTextChangedListener(new TextWatcher() {
            /* class com.fcsc2021.jakarta.MainActivity.AnonymousClass2 */

            public void afterTextChanged(Editable s) {
            }

            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
                ((TextView) MainActivity.this.findViewById(R.id.result_text)).setText("Check your flag:");
            }
        });
    }
}
```

Focus sur la méthode `onClick(View v)` :

```java
public void onClick(View v) {
    String candidate = ((TextView) MainActivity.this.findViewById(R.id.flag_input)).getText().toString();
    TextView tv2 = (TextView) MainActivity.this.findViewById(R.id.result_text);
    if (new Check(candidate).valid()) {
        tv2.setText("Correct!!");
    } else {
        tv2.setText("Nope.");
    }
}
```

Nous comprenons ici qu'un input est demandé à l'utilisateur \(proposition de flag\) et est stocké en tant que string dans la variable `candidate`. Le programme crée ensuite un objet de la class `Check()` et appelle la méthode `.valid()` qui renvoie si `candidate` est valide ou non.

Code de la class `Check` :

```java
package com.fcsc2021.jakarta;

public class Check {
    int[] enc = {11, 152, 177, 51, 145, 152, 153, 185, 26, 156, 177, 19, 177, 50, 156, 26, 156, 35, 176, 159, 185, 185, 185, 26, 19, 152, 177, 50, 144, 144, 176, 177, 26, 184, 190, 50, 11, 26, 51, 26, 26, 156, 19, 58, 148, 19, 176, 51, 26, 177, 58, 58, 144, 139, 152, 50, 185, 153, 177, 153, 144, 26, 176, 144, 50, 156, 145, 153, 156, 156};
    String flag;

    public Check(String _flag) {
        this.flag = _flag;
    }

    public boolean valid() {
        int len = this.flag.length();
        if (len != this.enc.length) {
            return false;
        }
        int[] A = new int[len];
        for (int i = 0; i < len; i++) {
            int ch = this.flag.charAt(((i * 37) + 1) % len);
            for (int j = 7; j >= 0; j--) {
                A[i] = A[i] ^ (((ch >> j) & 1) << (((j * 5) + 3) % 8));
            }
        }
        int res = 0;
        for (int i2 = 0; i2 < len; i2++) {
            res |= A[i2] ^ this.enc[i2];
        }
        if (res == 0) {
            return true;
        }
        return false;
    }
}
```

#### Comprendre la class `Check`

* La string `candidate` du `MainActivity` est représentée dans cette class par `this.flag`.
* Tout d'abord, nous voyons dans la méthode `valid()` que la proposition de flag doit faire la même longueur que l'array d'entier `enc` \(70 de long\) pour être valide.
* Juste en dessous le programme crée un array de int `A` de taille 70
* Ensuite il boucle tant que `i < len` \(`len` étant la taille de `flag`, de `A` et de `enc` donc 70\).
  * À chaque tour il met dans `ch` la valeur en int du charactère situé à l'endroit `((i * 37) + 1) % len` dans la string `flag` \(flag proposé par l'utilisateur et qui doit être vérifié\).
  * Dans cette boucle il crée une autre boucle. C'est à dire qu'a chaque tour de la première boucle la deuxième boucle tournera 8 fois.
    * Dans cette deuxième boucle il commence par faire `ch >> j` qui correspond à décaler `ch` sur la droite de `j` bit\(s\).
    * il fait ensuite un `&` \(AND, et logique\) entre le résultat de `ch >> j` et  `1`. Cette opération renvoie comme résultat soit `00000001` ou `00000000`.
    * Ensuite il décale le `00000001` ou `00000000` de `(((j * 5) + 3) % 8))` bit\(s\) sur la gauche.
    * Enfin il fait un `^` \(XOR\) entre le résultat du dernier décalage et `A[i]` . À chaque premier tour `A[i]` sera vide donc le XOR se fera sur `00000000` \(`null`\) mais dès le deuxième tour  de la deuxième boucle `A[i]` aura une vraie valeur vu que l'opérations `A[i] ^ ...` aura été stocké dedans. `A[i]` changera donc huit fois avant de passer à `A[i+1]`.
* Apres avoir remplis `A[]` de 70 valeurs le programme refait une autre boucle à l'extérieur qui va aussi boucler jusqu'à 70.
  * À l'intérieur de celle-ci il fait un `^` \(XOR\) entre `A[i2]` et `this.enc[i2]`. Ensuite il stocke dans `res` le résultat du `|` \(OR, ou logique\) entre `res` et le résultat du XOR.
  * J'ai testé le processus et la boucle finale et je me suis rendu compte d'un chose. Pour vous le le démontrer je vais tester l'opération avec `enc[0] = 11` donc `00001011` et `A[0]` au hasard une fois `00101001` puis `00001011`, dans les deux cas `res` vaudra 0 de base :
    * `res OR 00101001 XOR 00001011 = 00100010`
    * `res OR 00001011 XOR 00001011 = 0`
    * Étant donné que pour que `valid()` `return True` il faut que `res` soit égale à 0 à chaque fois. Je peux donc déduire que `A[i2]` doit être égale à `enc[i2]`.

```text
Valeurs renvoyées par ((j * 5) + 3) % 8)) :
1, 38, 5, 42, 9, 46, 13, 50, 17, 54, 21, 58, 25, 62, 29, 66, 33, 0, 37, 4, 41, 8, 45, 12, 49, 16, 53, 20, 57, 24, 61, 28, 65, 32, 69, 36, 3, 40, 7, 44, 11, 48, 15, 52, 19, 56, 23, 60, 27, 64, 31, 68, 35, 2, 39, 6, 43, 10, 47, 14, 51, 18, 55, 22, 59, 26, 63, 30, 67, 34
En gros, ca mélange tous les nombre présent entre 0 à 69.
```

Pour que le programme valide le flag il faut donc que `A[i2] == enc[i2]`. Par exemple pour `enc[0]` qui vaut 11 nous devons retrouver quel `ch` renvoie un `A[0] = 00001011` donc 11.

Le but premier va donc être de trouver quel `ch` \(valeur int d'un caractère ascii\) nous renvoie le `A[i]` correspondant à  `enc[i]` après être passé dans la moulinette de la deuxième boucle. Pour cela, nous allons tester la deuxième boucle \(celle qui fait les décalages\) avec tous les `ch` possible \(caractères ascii imprimables de 32 à 126\). En comparant `A[i]` avec `enc[i]` à chaque essai de `ch` nous pourrons donc ainsi définir quel caractère correspond au `enc[i]`. Enfin il suffit juste de remettre les valeurs de caractères dans le bon ordre étant donné que le `((i * 37) + 1) % len` à changé l'ordre.

#### Résolution avec Java

```java
import java.util.Arrays;

public class Main {
	public static int[] enc = {11, 152, 177, 51, 145, 152, 153, 185, 26, 156, 177, 19, 177, 50, 156, 26, 156, 35, 176, 159, 185, 185, 185, 26, 19, 152, 177, 50, 144, 144, 176, 177, 26, 184, 190, 50, 11, 26, 51, 26, 26, 156, 19, 58, 148, 19, 176, 51, 26, 177, 58, 58, 144, 139, 152, 50, 185, 153, 177, 153, 144, 26, 176, 144, 50, 156, 145, 153, 156, 156};
	public static int[] A = new int[70];
	public static int[] stock = new int[70];
	public static int[] disorder = new int[70];
	public static int len = 70;
	public static char[] flag = new char[70];
	
	public static void main(String[] args) {
		// boucle jusqu'à 70 pour checker chaque enc[i].
		for (int i = 0; i < len; i++) {
			// boucle de 32 à 126 pour tester chaque char ascii dans la moulinette de décalage.
			// si A[i] = enc[i] c'est qu'il a trouvé le bon ch.
			for (int ch = 32; ch <= 126 && A[i] != enc[i]; ch++) {
				A[i] = 0;
				for (int j = 7; j >= 0; j--) {
					A[i] = A[i] ^ (((ch >> j) & 1) << (((j * 5) + 3) % 8));
				}
				if(A[i] == enc[i]) {
						stock[i] = ch;
						// System.out.println(stock[i]);
				}
			}
			// stockages des positions de désordre.
			disorder[i] = ((i * 37) + 1) % len;
			// System.out.println(stockB[i]);
		}
		// remise dans l'ordre en utilisant les index stockés dans disorder.
		for (int i2 = 0; i2 < len; i2++) {
			flag[disorder[i2]] = (char)stock[i2];
		}
		System.out.println(Arrays.toString(flag));
	}
}
```

#### Flag

```text
[F, C, S, C, {, 6, d, f, 7, 2, 3, a, a, 3, 3, b, 1, a, a, 8, d, 6, 0, 4, 0, 6, 9, a, 6, 9, 3, e, 5, 9, 9, 0, d, 4, 1, 1, a, 7, f, 7, a, 7, 1, 6, 9, b, 7, 0, e, 6, 9, 4, b, 0, b, d, f, 4, d, 2, 6, a, a, 9, e, }]

FCSC{6df723aa33b1aa8d604069a693e5990d411a7f7a7169b70e694b0bdf4d26aa9e}
```

## Sources & Aides

[https://en.wikipedia.org/wiki/Android\_application\_package](https://en.wikipedia.org/wiki/Android_application_package)  
[https://reverseengineering.stackexchange.com/questions/18170/what-are-the-tools-use-for-reverse-engineering-android-apk](https://reverseengineering.stackexchange.com/questions/18170/what-are-the-tools-use-for-reverse-engineering-android-apk)  
[https://chris-yn-chen.medium.com/apk-reverse-engineering-df7ed8cec191](https://chris-yn-chen.medium.com/apk-reverse-engineering-df7ed8cec191)  
[https://github.com/skylot/jadx](https://github.com/skylot/jadx)  
[https://medium.com/swlh/reverse-engineering-and-modifying-an-android-game-apk-ctf-c617151b874c](https://medium.com/swlh/reverse-engineering-and-modifying-an-android-game-apk-ctf-c617151b874c)  
[https://yasoob.me/posts/reverse-engineering-android-apps-apktool/](https://yasoob.me/posts/reverse-engineering-android-apps-apktool/)  
[https://www.jmdoudoux.fr/java/dej/chap-techniques-base.htm](https://www.jmdoudoux.fr/java/dej/chap-techniques-base.htm)  
[https://www.geeksforgeeks.org/new-operator-java/](https://www.geeksforgeeks.org/new-operator-java/)  
[https://www.w3schools.com/java/ref\_string\_charat.asp](https://www.w3schools.com/java/ref_string_charat.asp)  
[https://www.tutorialspoint.com/java/java\_basic\_operators.htm\#:~:text=Java%20defines%20several%20bitwise%20operators,short%2C%20char%2C%20and%20byte.&text=Binary%20AND%20Operator%20copies%20a,it%20exists%20in%20both%20operands.&text=Binary%20OR%20Operator%20copies%20a%20bit%20if%20it%20exists%20in%20either%20operand.&text=Binary%20Left%20Shift%20Operator.](https://www.tutorialspoint.com/java/java_basic_operators.htm#:~:text=Java%20defines%20several%20bitwise%20operators,short%2C%20char%2C%20and%20byte.&text=Binary%20AND%20Operator%20copies%20a,it%20exists%20in%20both%20operands.&text=Binary%20OR%20Operator%20copies%20a%20bit%20if%20it%20exists%20in%20either%20operand.&text=Binary%20Left%20Shift%20Operator.)

