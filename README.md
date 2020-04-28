# StudyWinCrosscmpile

## Учебный пример по кросскомпиляции.

* Development platform - Linux
* Target platform - Windows

Программа вычисляет хэш md5 от самой себя, используя функции Win32 API

Ипользованы функции из раздела Cryptography (advapi32), являющиеся на данный момент устаревшими (deprecated) 

## Подкаталог *anothe_example_more_complex*

Многомодульный проект вычисления хэша файла. Вычисление хэша выведено в отдельный модуль. Обработка ошибок выполнена на классах исключений стандартной библиотеки Си++. Реализован интерактивный пользовательский интерфейс, позволяющий выбрать файл и алгоритм.

* Development platform - Linux
* Target platform - Windows
 
Ипользованы функции из раздела Cryptography New Generation (bcrypt), являющиеся на данный основными (поддржка начиная с Windows 7, неполная поддержка Windows Vista)
