# InscriptionnotauthenticatedconditionResponse

An Inscriptionnotauthenticatedcondition Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiInscriptionnotauthenticatedconditionID** | **number** | The unique ID of the Inscriptionnotauthenticatedcondition | [default to undefined]
**fkiInscriptionnotauthenticatedconditiontypeID** | **number** | The unique ID of the Inscriptionnotauthenticatedconditiontype | [default to undefined]
**sInscriptionnotauthenticatedconditiontypeNameX** | **string** | The name of the Inscriptionnotauthenticatedconditiontype in the language of the requester | [default to undefined]
**fkiInscriptionnotauthenticatedID** | **number** | The unique ID of the Inscriptionnotauthenticated. | [default to undefined]
**bInscriptionnotauthenticatedconditionFilled** | **boolean** | Can access attachment when we clone a user | [default to undefined]
**dtInscriptionnotauthenticatedconditionCompleted** | **string** | The date the Inscriptionnotauthenticatedcondition was completed | [optional] [default to undefined]
**dtInscriptionnotauthenticatedconditionDue** | **string** | The date the Inscriptionnotauthenticatedcondition is due | [optional] [default to undefined]
**tInscriptionnotauthenticatedconditionComment** | **string** | The comment of the Inscriptionnotauthenticatedcondition | [default to undefined]

## Example

```typescript
import { InscriptionnotauthenticatedconditionResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InscriptionnotauthenticatedconditionResponse = {
    pkiInscriptionnotauthenticatedconditionID,
    fkiInscriptionnotauthenticatedconditiontypeID,
    sInscriptionnotauthenticatedconditiontypeNameX,
    fkiInscriptionnotauthenticatedID,
    bInscriptionnotauthenticatedconditionFilled,
    dtInscriptionnotauthenticatedconditionCompleted,
    dtInscriptionnotauthenticatedconditionDue,
    tInscriptionnotauthenticatedconditionComment,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
