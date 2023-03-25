#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<netdb.h>
#include<arpa/inet.h>
#include<string.h>
#include<errno.h>
#include<openssl/err.h>
#include<openssl/ssl.h>

struct Tense {
    char person[50];
    char verb_conj[100];
    char person_add[100];
} tense_present[6], tense_imparfait[6], tense_futur_simple[6], tense_passe_compose[6];

void tense_clear(void)
{
    memset(tense_present, 0, sizeof(tense_present));
    memset(tense_imparfait, 0, sizeof(tense_present));
    memset(tense_futur_simple, 0, sizeof(tense_present));
    memset(tense_passe_compose, 0, sizeof(tense_present));
}


void tense_print(struct Tense *t)
{
    int i;
    for (i = 0; i < 6; i++)
        printf("%s %s %s\n", t[i].person, t[i].person_add, t[i].verb_conj);
    puts("-----------\n");
}

void spaces_remove(char *str)
{
    char *ptr;
    ptr = strchr(str, ' ');
    if (!ptr)
        return;
    *ptr = 0;
}

void tense_clean(struct Tense *t)
{
    int i;
    for (i = 0; i < 6; i++) {
        spaces_remove(t[i].person);
        spaces_remove(t[i].verb_conj);
        spaces_remove(t[i].person_add);
    }
}

void brackets_remove(char *str)
{
    char *ptr;
    char *end;

    ptr = strchr(str, '(');
    if (!ptr)
        return;
    end = strchr(str, ')');
    if (!end)
        return;
    strcpy(ptr, end + 1);
}

int response_scrap(char *path, char *response)
{
    int sock;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new() failed.\n");
        return -1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *peer_address;
    if (getaddrinfo("konjugator.reverso.net", "443", &hints, &peer_address)) {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", errno);
        return -1;
    }

    sock = socket(peer_address->ai_family, peer_address->ai_socktype, peer_address->ai_protocol);
    if (sock < 3) {
        fprintf(stderr, "sockeet() failed. (%d)\n", errno);
        return -1;
    }

    if (connect(sock, peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", errno);
        return -1;
    }
    freeaddrinfo(peer_address);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "SSL_new() failed.\n");
        return -1;
    }

    if (!SSL_set_tlsext_host_name(ssl, "konjugator.reverso.net")) {
        fprintf(stderr, "SSL_set_tlsext_host_name() failed.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) == -1) {
        fprintf(stderr, "SSL_connect() failed.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "SSL_get_peer_certificate() failed.\n");
        return -1;
    }

    /*
    char *tmp;
    if ((tmp = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0))) {
        printf("subject: %s\n", tmp);
        OPENSSL_free(tmp);
    }

    if ((tmp = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0))) {
        printf("issuer: %s\n", tmp);
        OPENSSL_free(tmp);
    }
    */

    X509_free(cert);

    /* get response */
    char buffer[2048] = { 0 };

    sprintf(buffer, "GET %s HTTP/1.1\r\n", path);
    sprintf(buffer + strlen(buffer), "Host: konjugator.reverso.net:443\r\n");
    sprintf(buffer + strlen(buffer), "Connection: close\r\n");
    sprintf(buffer + strlen(buffer), "User-Agent: https_simple\r\n");
    sprintf(buffer + strlen(buffer), "\r\n");

    SSL_write(ssl, buffer, strlen(buffer));

    unsigned int offset = 0;
    while(1) {
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received < 1) {
            /*
            printf("\nConnection closed by peer.\n");
            */
            break;
        }
        strncpy(response + offset, buffer, bytes_received);
        offset += bytes_received;
    }
    response[offset] = 0;

    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}

char *ending_get(char *verb_conj, char *ending0, char *ending1, char *ending2)
{
    int verb_conj_len = strlen(verb_conj);
    int endings_len = strlen(ending0);

    if (strcmp(&verb_conj[verb_conj_len - endings_len], ending0) == 0) {
        verb_conj[verb_conj_len - endings_len] = 0;
        return ending0;
    }

    endings_len = strlen(ending1);

    if (*ending1 != 0) {
        if (strcmp(&verb_conj[verb_conj_len - endings_len], ending1) == 0) {
            verb_conj[verb_conj_len - endings_len] = 0;
            return ending1;
        }
    }

    endings_len = strlen(ending2);

    if (*ending2 != 0) {
        if (strcmp(&verb_conj[verb_conj_len - endings_len], ending2) == 0) {
            verb_conj[verb_conj_len - endings_len] = 0;
            return ending2;
        }
    }

    return NULL;
}

#define COLOR_RED "rgb(170, 0, 0);"
#define COLOR_VIOLET "rgb(238,130,238);"
#define COLOR_YELLOW "rgb(255, 255, 0);"
#define COLOR_GREEN "rgb(0, 170, 0);"
#define COLOR_BLUE "rgb(0, 180, 255);"

void anki_deck_card_append(char *verb)
{
    FILE *f = fopen("ankideck.txt", "a+");
    fprintf(f, "%s\t\"Key:<br>", verb);

    char *ending;
    /* key: je */
    ending = ending_get(tense_present[0].verb_conj, "e", "s", "x");
    if (ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_RED "\"\">%s</span>%s<br>",
                tense_present[0].person, tense_present[0].verb_conj, ending);
    } else {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_present[0].person, tense_present[0].verb_conj);
    }

    /* tu */
    ending = ending_get(tense_present[1].verb_conj, "es", "s", "x");
    if (ending) {
        if (strcmp(tense_present[1].verb_conj, tense_present[0].verb_conj) != 0) {
            fprintf(f, "%s <span style=\"\"color: " COLOR_GREEN "\"\">%s</span>%s<br>",
                    tense_present[1].person, tense_present[1].verb_conj, ending);
        }
    } else {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_present[1].person, tense_present[1].verb_conj);
    }
    /* il */
    ending = ending_get(tense_present[2].verb_conj, "e", "t", "");
    if (ending) {
        if (strcmp(tense_present[2].verb_conj, tense_present[0].verb_conj) != 0) {
            fprintf(f, "%s <span style=\"\"color: " COLOR_GREEN "\"\">%s</span>%s<br>",
                    tense_present[2].person, tense_present[2].verb_conj, ending);
        }
    } else {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_present[2].person, tense_present[2].verb_conj);
    }

    /* key: ns */
    ending = ending_get(tense_present[3].verb_conj, "ons", "", "");
    if (ending) {
        if (strcmp(tense_present[3].verb_conj, tense_present[0].verb_conj) == 0) {
            fprintf(f, "ns <span style=\"\"color: " COLOR_RED "\"\">%s</span>%s<br>",
                    tense_present[3].verb_conj, ending);
        } else {
            fprintf(f, "ns <span style=\"\"color: " COLOR_BLUE "\"\">%s</span>%s<br>",
                    tense_present[3].verb_conj, ending);
        }
    } else {
        fprintf(f, "ns <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
               tense_present[3].verb_conj);
    }

    /* vous */
    ending = ending_get(tense_present[4].verb_conj, "ez", "", "");
    if (ending) {
        if (strcmp(tense_present[4].verb_conj, tense_present[3].verb_conj) != 0) {
            fprintf(f, "vs <span style=\"\"color: " COLOR_GREEN "\"\">%s</span>%s<br>",
                    tense_present[4].verb_conj, ending);
        }
    } else {
        fprintf(f, "vs <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_present[4].verb_conj);
    }

    /* key: ils */
    ending = ending_get(tense_present[5].verb_conj, "ent", "", "");
    if (ending) {
        if (strcmp(tense_present[5].verb_conj, tense_present[0].verb_conj) == 0) {
            fprintf(f, "ils <span style=\"\"color: " COLOR_RED "\"\">%s</span>%s<br>",
                    tense_present[5].verb_conj, ending);
        } else if (strcmp(tense_present[5].verb_conj, tense_present[3].verb_conj) == 0) {
            fprintf(f, "ils <span style=\"\"color: " COLOR_BLUE "\"\">%s</span>%s<br>",
                    tense_present[5].verb_conj, ending);
        } else {
            fprintf(f, "ils <span style=\"\"color: " COLOR_VIOLET "\"\">%s</span>%s<br>",
                    tense_present[5].verb_conj, ending);
        }
    } else {
        fprintf(f, "ils <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_present[5].verb_conj);
    }

    /* key: passé composé */
    fprintf(f, "%s %s %s<br>", tense_passe_compose[0].person, tense_passe_compose[0].person_add, tense_passe_compose[0].verb_conj);

    fprintf(f, "<br>exeptions:<br>");

    fprintf(f, "imparfait:<br>");
    /* imparfait exeptions */
    ending = ending_get(tense_imparfait[0].verb_conj, "ais", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_imparfait[0].person, tense_imparfait[0].verb_conj);
    } else if (strcmp(tense_imparfait[0].verb_conj, tense_present[3].verb_conj) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_imparfait[0].person, tense_imparfait[0].verb_conj, ending);
    }
    ending = ending_get(tense_imparfait[1].verb_conj, "ais", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_imparfait[1].person, tense_imparfait[1].verb_conj);
    } else if (strcmp(tense_imparfait[1].verb_conj, tense_present[3].verb_conj) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_imparfait[1].person, tense_imparfait[1].verb_conj, ending);
    }
    ending = ending_get(tense_imparfait[2].verb_conj, "ait", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_imparfait[2].person, tense_imparfait[2].verb_conj);
    } else if (strcmp(tense_imparfait[2].verb_conj, tense_present[3].verb_conj) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_imparfait[2].person, tense_imparfait[2].verb_conj, ending);
    }
    ending = ending_get(tense_imparfait[3].verb_conj, "ions", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_imparfait[3].person, tense_imparfait[3].verb_conj);
    } else if (strcmp(tense_imparfait[3].verb_conj, tense_present[3].verb_conj) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_imparfait[3].person, tense_imparfait[3].verb_conj, ending);
    }
    ending = ending_get(tense_imparfait[4].verb_conj, "iez", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_imparfait[4].person, tense_imparfait[3].verb_conj);
    } else if (strcmp(tense_imparfait[4].verb_conj, tense_present[3].verb_conj) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_imparfait[4].person, tense_imparfait[3].verb_conj, ending);
    }
    ending = ending_get(tense_imparfait[5].verb_conj, "aient", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_imparfait[5].person, tense_imparfait[5].verb_conj);
    } else if (strcmp(tense_imparfait[5].verb_conj, tense_present[3].verb_conj) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_imparfait[5].person, tense_imparfait[5].verb_conj, ending);
    }

    fprintf(f, "futur:<br>");
    /* futur exeptions */

    /* manipulate verb */
    if (strcmp(&verb[strlen(verb) - 2], "re") == 0) {
        verb[strlen(verb) - 1] = 0;
    } else if (strcmp(&verb[strlen(verb) - 3], "oir") == 0) {
        verb[strlen(verb) - 3] = 'r';
        verb[strlen(verb) - 2] = 0;
    }

    ending = ending_get(tense_futur_simple[0].verb_conj, "ai", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_futur_simple[0].person, tense_futur_simple[0].verb_conj);
    } else if (strcmp(tense_futur_simple[0].verb_conj, verb) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_futur_simple[0].person, tense_futur_simple[0].verb_conj, ending);
    }
    ending = ending_get(tense_futur_simple[1].verb_conj, "as", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_futur_simple[1].person, tense_futur_simple[1].verb_conj);
    } else if (strcmp(tense_futur_simple[1].verb_conj, verb) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_futur_simple[1].person, tense_futur_simple[1].verb_conj, ending);
    }
    ending = ending_get(tense_futur_simple[2].verb_conj, "a", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_futur_simple[2].person, tense_futur_simple[2].verb_conj);
    } else if (strcmp(tense_futur_simple[2].verb_conj, verb) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_futur_simple[2].person, tense_futur_simple[2].verb_conj, ending);
    }
    ending = ending_get(tense_futur_simple[3].verb_conj, "ons", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_futur_simple[3].person, tense_futur_simple[3].verb_conj);
    } else if (strcmp(tense_futur_simple[3].verb_conj, verb) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_futur_simple[3].person, tense_futur_simple[3].verb_conj, ending);
    }
    ending = ending_get(tense_futur_simple[4].verb_conj, "ez", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_futur_simple[4].person, tense_futur_simple[4].verb_conj);
    } else if (strcmp(tense_futur_simple[4].verb_conj, verb) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_futur_simple[4].person, tense_futur_simple[4].verb_conj, ending);
    }
    ending = ending_get(tense_futur_simple[5].verb_conj, "ont", "", "");
    if (!ending) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span><br>",
                tense_futur_simple[5].person, tense_futur_simple[5].verb_conj);
    } else if (strcmp(tense_futur_simple[5].verb_conj, verb) != 0) {
        fprintf(f, "%s <span style=\"\"color: " COLOR_YELLOW "\"\">%s</span>%s<br>",
                tense_futur_simple[5].person, tense_futur_simple[5].verb_conj, ending);
    }
    

    fputc('"', f);
    fputc('\n', f);
    fclose(f);

    fprintf(stdout, "-> anki card created\n");
}

void unicode_replace(char *str, char *search, char *replace)
{
    str = strstr(str, search);
    if (!str)
        return;

    int str_len = strlen(str);
    int search_len = strlen(search);
    int replace_len = strlen(replace);

    strncpy(str + replace_len, str + search_len, strlen(str + search_len));
    strncpy(str, replace, replace_len);
    *(str + (str_len - search_len) + replace_len) = 0;
}

void verb_unicode(char *verb)
{
    unicode_replace(verb, "&#233;", "é");
    unicode_replace(verb, "&#232;", "è");
    unicode_replace(verb, "&#234;", "ê");
    unicode_replace(verb, "&#238;", "î");
}

void verb_scrap(char *verb)
{
    tense_clear();
    fprintf(stdout, "looking for verb...: %s\n", verb);
    char path[100];
    sprintf(path, "/konjugation-franzosisch-verb-%s.html", verb);

    char response[300000];
    if (response_scrap(path, response)) {
        fprintf(stderr, "-> [ERR] failed to scrap response from verb: %s\n", verb);
        return;
    }

    char *err;
    /* checking for errors */
    err = strstr(response, "Das gesuchte Verb entspricht keinem bekannten Konjugationsschema");
    if (err) {
        fprintf(stderr, "-> [ERR] don't find the verb\n");
        return;
    }
    /* similar verb was found */
    err = strstr(response, "Ergebnis der Ähnlichkeitssuche");
    if (err) {
        char *similar_verb = strstr(response, "ch_lblVerb");
        char *end;
        similar_verb = strchr(similar_verb, '>');
        similar_verb++;
        end = strchr(similar_verb, '<');
        strncpy(verb, similar_verb, end - similar_verb);
        verb[end - similar_verb] = 0;
        verb_unicode(verb);
        fprintf(stdout, "-> similar verb was found %s\n", verb);
    }

    fprintf(stdout, "-> found verb: %s\n", verb);

    char *ptr = strstr(response, "Indicatif");
    if (!ptr) {
        fprintf(stderr, "-> [ERR] can't find Indicatif startpoint\n");
        return;
    }
    char *end;
    /* tense present */
    ptr = strstr(ptr, "Présent");

    int i = 0;
    ptr = strstr(ptr, "<ul") + 1;
    while (*(ptr = strchr(ptr, '<') + 1) == 'l') {
        ptr = strstr(ptr, "<i");
        ptr = strchr(ptr, '>') + 1;
        end = strchr(ptr, '<');
        strncpy(tense_present[i].person, ptr, end - ptr);
        ptr = strstr(ptr, "<i");
        ptr = strchr(ptr, '>') + 1;
        end = strchr(ptr, '<');
        strncpy(tense_present[i].verb_conj, ptr, end - ptr);
        brackets_remove(tense_present[i].verb_conj);
        ptr = strstr(ptr, "/li");
        i++;
    }
    tense_clean(tense_present);

    /* Imparfait */
    ptr = strstr(ptr, "Imparfait");

    i = 0;
    ptr = strstr(ptr, "<ul") + 1;
    while (*(ptr = strchr(ptr, '<') + 1) == 'l') {
        ptr = strstr(ptr, "<i");
        ptr = strchr(ptr, '>') + 1;
        end = strchr(ptr, '<');
        strncpy(tense_imparfait[i].person, ptr, end - ptr);
        ptr = strstr(ptr, "<i");
        ptr = strchr(ptr, '>') + 1;
        end = strchr(ptr, '<');
        strncpy(tense_imparfait[i].verb_conj, ptr, end - ptr);
        brackets_remove(tense_imparfait[i].verb_conj);
        ptr = strstr(ptr, "/li");
        i++;
    }
    tense_clean(tense_imparfait);

    /* Futer simple */
    ptr = strstr(ptr, "Futur");

    i = 0;
    ptr = strstr(ptr, "<ul") + 1;
    while (*(ptr = strchr(ptr, '<') + 1) == 'l') {
        ptr = strstr(ptr, "<i");
        ptr = strchr(ptr, '>') + 1;
        end = strchr(ptr, '<');
        strncpy(tense_futur_simple[i].person, ptr, end - ptr);
        ptr = strstr(ptr, "<i");
        ptr = strchr(ptr, '>') + 1;
        end = strchr(ptr, '<');
        strncpy(tense_futur_simple[i].verb_conj, ptr, end - ptr);
        brackets_remove(tense_futur_simple[i].verb_conj);
        ptr = strstr(ptr, "/li");
        i++;
    }
    tense_clean(tense_futur_simple);

    /* Passé Composeé */
    ptr = strstr(ptr, "Passé composé");
    i = 0;
    ptr = strstr(ptr, "<ul") + 1;
    while (*(ptr = strchr(ptr, '<') + 1) == 'l' && i < 6) { /* i < 6 temp solution for passe compose 2 */
        ptr = strstr(ptr, "<i");
        ptr = strchr(ptr, '>') + 1;
        end = strchr(ptr, '<');
        strncpy(tense_passe_compose[i].person, ptr, end - ptr);
        ptr = strstr(ptr, "<i");
        ptr = strchr(ptr, '>') + 1;
        end = strchr(ptr, '<');
        strncpy(tense_passe_compose[i].person_add, ptr, end - ptr);
        ptr = strstr(ptr, "<i");
        ptr = strchr(ptr, '>') + 1;
        end = strchr(ptr, '<');
        strncpy(tense_passe_compose[i].verb_conj, ptr, end - ptr);
        brackets_remove(tense_passe_compose[i].verb_conj);
        ptr = strstr(ptr, "/li");
        i++;
    }
    tense_clean(tense_passe_compose);

    anki_deck_card_append(verb);
}

int main(void)
{
#if 0
    char verb[150] = "completer";
    verb_scrap(verb);
#else
    FILE *f = fopen("verb_list.txt", "r");
    char verb[150];

    while (fscanf(f, "%s", verb) != EOF)
        verb_scrap(verb);
    fclose(f);
#endif

    return 0;
}
