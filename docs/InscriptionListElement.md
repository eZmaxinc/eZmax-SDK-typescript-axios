# InscriptionListElement

A Inscription List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiInscriptionID** | **number** | The unique ID of the Inscription. | [default to undefined]
**pkiInscriptionnotauthenticatedID** | **number** | The unique ID of the Inscriptionnotauthenticated. | [optional] [default to undefined]
**fkiInscriptiontypeID** | **number** | The unique ID of the Inscriptiontype | [default to undefined]
**sInscriptiontypeNameX** | **string** | The name of the Inscriptiontype in the language of the requester | [default to undefined]
**eInscriptionStep** | [**FieldEInscriptionStep**](FieldEInscriptionStep.md) |  | [default to undefined]
**sInscriptionCivicend** | **string** | The civicend of the Inscription | [default to undefined]
**sInscriptionMLS** | **string** | The mls of the Inscription | [optional] [default to undefined]
**dInscriptionSaleprice** | **string** | The saleprice of the Inscription | [default to undefined]
**dInscriptionRentprice** | **string** | The rentprice of the Inscription | [default to undefined]
**dtInscriptionDate** | **string** | The date of the Inscription | [optional] [default to undefined]
**dtInscriptionExpirationdate** | **string** | The expirationdate of the Inscription | [optional] [default to undefined]
**dtInscriptionNotarydate** | **string** | The notarydate of the Inscription | [optional] [default to undefined]
**bInscriptionIsactive** | **boolean** | Whether the inscription is active or not | [default to undefined]
**bInscriptionArchived** | **boolean** | Whether the inscription is archived or not | [default to undefined]
**bInscriptionInspection** | **boolean** | Whether the inscription can be acces by an inspector | [optional] [default to undefined]
**dtInscriptionnotauthenticatedNotaryscheduledate** | **string** | The notaryscheduledate of the Inscriptionnotauthenticated | [optional] [default to undefined]
**dtInscriptionnotauthenticatedTransactiondate** | **string** | The transactiondate of the Inscriptionnotauthenticated | [optional] [default to undefined]
**dtInscriptionnotauthenticatedTransactiondateReal** | **string** | The transactiondatereal of the Inscriptionnotauthenticated | [optional] [default to undefined]
**bInscriptionnotauthenticatedConditional** | **boolean** | Whether the inscriptionnotauthenticated is conditional | [optional] [default to undefined]
**bInscriptionnotauthenticatedIsactive** | **boolean** | Whether the inscriptionnotauthenticated is active or not | [optional] [default to undefined]
**sAddressCivic** | **string** | The Civic number. | [optional] [default to undefined]
**sAddressStreet** | **string** | The Street Name | [optional] [default to undefined]
**sAddressSuite** | **string** | The Suite or appartment number | [optional] [default to undefined]
**sAddressCity** | **string** | The City name | [optional] [default to undefined]
**sAddressZip** | **string** | The Postal/Zip Code  The value must be entered without spaces | [optional] [default to undefined]
**sProvinceNameX** | **string** | The name of the Province in the language of the requester | [optional] [default to undefined]
**sCountryNameX** | **string** | The name of the Country in the language of the requester | [optional] [default to undefined]
**iInscriptionnotauthenticatedCanceled** | **number** | The numbre of inscriptionnotauthenticated was canceled in this Inscription | [default to undefined]
**bAllowedCopyintoinscriptionedm** | **boolean** | Whether we are allowed to copy into the Inscription EDM | [default to undefined]

## Example

```typescript
import { InscriptionListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InscriptionListElement = {
    pkiInscriptionID,
    pkiInscriptionnotauthenticatedID,
    fkiInscriptiontypeID,
    sInscriptiontypeNameX,
    eInscriptionStep,
    sInscriptionCivicend,
    sInscriptionMLS,
    dInscriptionSaleprice,
    dInscriptionRentprice,
    dtInscriptionDate,
    dtInscriptionExpirationdate,
    dtInscriptionNotarydate,
    bInscriptionIsactive,
    bInscriptionArchived,
    bInscriptionInspection,
    dtInscriptionnotauthenticatedNotaryscheduledate,
    dtInscriptionnotauthenticatedTransactiondate,
    dtInscriptionnotauthenticatedTransactiondateReal,
    bInscriptionnotauthenticatedConditional,
    bInscriptionnotauthenticatedIsactive,
    sAddressCivic,
    sAddressStreet,
    sAddressSuite,
    sAddressCity,
    sAddressZip,
    sProvinceNameX,
    sCountryNameX,
    iInscriptionnotauthenticatedCanceled,
    bAllowedCopyintoinscriptionedm,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
