# collaudoio/azione

L'azione GitHub di **[Collaudo](https://collaudo.io)**: esegue nella CI del tuo repository l'ordine del
servizio di Collaudo (la prova, la suite, le varianti del codice) e ne spedisce i risultati, firmati
dall'identità OIDC del workflow. _The GitHub Action of Collaudo: it runs the Collaudo service's order in
your repository's CI and sends back the raw results, signed by the workflow's OIDC identity._

**È muta.** Non decide niente: non sa che cosa sia un rosso o un verde «per la ragione giusta». Scrive i
file che l'ordine indica, applica e ripristina le sostituzioni testuali, esegue la suite col reporter JSON,
legge e impronta i file, e spedisce. Il giudizio e il verdetto firmato stanno nel servizio.

**Permessi minimi.** Il job che la usa dichiara solo:

```yaml
permissions:
  contents: read
  id-token: write
```

Nessun segreto: l'identità è il token OIDC di GitHub, con audience `collaudo.io`. L'azione non stampa mai
il token né l'ordine.

> Anteprima: il servizio non è ancora in linea. Il modo di riferirla (versione e workflow fidato) può
> cambiare prima della prima versione.

Collaudo e COLLAUDOIO sono marchi di Andrea Guido Caiulo (domanda UIBM n. 302026000163264). Il codice qui è
generato dal repository privato di Collaudo; i contributi non si accettano da qui.
