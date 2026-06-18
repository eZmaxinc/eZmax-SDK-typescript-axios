# InscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Request

Request for POST /1/object/inscriptionnotauthenticated/{pkiInscriptionnotauthenticatedID}/fillInscriptionnotauthenticatedcondition

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_objInscriptionnotauthenticatedcondition** | [**Array&lt;CustomInscriptionnotauthenticatedconditionRequest&gt;**](CustomInscriptionnotauthenticatedconditionRequest.md) |  | [default to undefined]
**dtInscriptionnotauthenticatedTransactiondateReal** | **string** | The transactiondatereal of the Inscriptionnotauthenticated | [optional] [default to undefined]

## Example

```typescript
import { InscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Request = {
    a_objInscriptionnotauthenticatedcondition,
    dtInscriptionnotauthenticatedTransactiondateReal,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
