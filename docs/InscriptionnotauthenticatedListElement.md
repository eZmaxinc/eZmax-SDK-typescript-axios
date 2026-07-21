# InscriptionnotauthenticatedListElement

A Inscriptionnotauthenticated List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiInscriptionID** | **number** | The unique ID of the Inscription. | [default to undefined]
**pkiInscriptionnotauthenticatedID** | **number** | The unique ID of the Inscriptionnotauthenticated. | [optional] [default to undefined]
**fkiInscriptiontypeID** | **number** | The unique ID of the Inscriptiontype | [default to undefined]
**sInscriptiontypeNameX** | **string** | The name of the Inscriptiontype in the language of the requester | [default to undefined]
**fkiInscriptionbuildingtypeID** | **number** | The unique ID of the Inscriptionbuildingtype | [default to undefined]
**sInscriptionbuildingtypeNameX** | **string** | The name of the Inscriptionbuildingtype in the language of the requester | [default to undefined]
**fkiInscriptioncategoryID** | **number** | The unique ID of the Inscriptioncategory | [default to undefined]
**sInscriptioncategoryNameX** | **string** | The name of the Inscriptioncategory in the language of the requester | [default to undefined]
**fkiBuyercontractID** | **number** | The unique ID of the Buyercontract | [optional] [default to undefined]
**sBuyercontractContract** | **string** | The number of the Buyercontract | [optional] [default to undefined]
**eInscriptionStep** | [**FieldEInscriptionStep**](FieldEInscriptionStep.md) |  | [default to undefined]
**eInscriptionType** | [**FieldEInscriptionType**](FieldEInscriptionType.md) |  | [default to undefined]
**sInscriptionCivicend** | **string** | The civicend of the Inscription | [default to undefined]
**sInscriptionMLS** | **string** | The mls of the Inscription | [optional] [default to undefined]
**sInscriptionContract** | **string** | The sale contract number | [optional] [default to undefined]
**dInscriptionSaleprice** | **string** | The saleprice of the Inscription | [default to undefined]
**dInscriptionRentprice** | **string** | The rentprice of the Inscription | [default to undefined]
**dtInscriptionDate** | **string** | The date of the Inscription | [optional] [default to undefined]
**dtInscriptionExpirationdate** | **string** | The expirationdate of the Inscription | [optional] [default to undefined]
**dtInscriptionNotarydate** | **string** | The notarydate of the Inscription | [optional] [default to undefined]
**bInscriptionInspection** | **boolean** | Whether the inscription can be acces by an inspector | [optional] [default to undefined]
**bInscriptionIsactive** | **boolean** | Whether the inscription is active or not | [default to undefined]
**bInscriptionArchived** | **boolean** | Whether the inscription is archived or not | [default to undefined]
**dtInscriptionnotauthenticatedNotaryscheduledate** | **string** | The notaryscheduledate of the Inscriptionnotauthenticated | [optional] [default to undefined]
**dtInscriptionnotauthenticatedTransactiondate** | **string** | The transactiondate of the Inscriptionnotauthenticated | [optional] [default to undefined]
**dtInscriptionnotauthenticatedTransactiondateReal** | **string** | The transactiondatereal of the Inscriptionnotauthenticated | [optional] [default to undefined]
**bInscriptionnotauthenticatedConditional** | **boolean** | Whether the inscriptionnotauthenticated is conditional | [optional] [default to undefined]
**bInscriptionnotauthenticatedIsactive** | **boolean** | Whether the inscriptionnotauthenticated is active or not | [optional] [default to undefined]
**bInscriptionnotauthenticatedDraft** | **boolean** | Whether the inscriptionnotauthenticated is a draft or not | [optional] [default to undefined]
**sAddressCivic** | **string** | The Civic number. | [optional] [default to undefined]
**sAddressStreet** | **string** | The Street Name | [optional] [default to undefined]
**sAddressSuite** | **string** | The Suite or appartment number | [optional] [default to undefined]
**sAddressCity** | **string** | The City name | [optional] [default to undefined]
**sAddressZip** | **string** | The Postal/Zip Code  The value must be entered without spaces | [optional] [default to undefined]
**fkiProvinceID** | **number** | The unique ID of the Province.  Here are some common values (Complete list must be retrieved from API):  |Value|Description| |-|-| |1|(Canada) Alberta |2|(Canada) British Columbia| |3|(Canada) Manitoba| |3|(Canada) Manitoba| |4|(Canada) New Brunswick| |5|(Canada) Newfoundland| |6|(Canada) Northwest Territories| |7|(Canada) Nova Scotia| |8|(Canada) Nunavut| |9|(Canada) Ontario| |10|(Canada) Prince Edward Island| |11|(Canada) Quebec| |12|(Canada) Saskatchewan| |13|(Canada) Yukon| |14|(United-States) Alabama| |15|(United-States) Alaska| |16|(United-States) Arizona| |17|(United-States) Arkansas| |18|(United-States) California| |19|(United-States) Colorado| |20|(United-States) Connecticut| |21|(United-States) Delaware| |22|(United-States) District of Columbia| |23|(United-States) Florida| |24|(United-States) Georgia| |25|(United-States) Hawaii| |26|(United-States) Idaho| |27|(United-States) Illinois| |28|(United-States) Indiana| |29|(United-States) Iowa| |30|(United-States) Kansas| |31|(United-States) Kentucky| |32|(United-States) Louisiane| |33|(United-States) Maine| |34|(United-States) Maryland| |35|(United-States) Massachusetts| |36|(United-States) Michigan| |37|(United-States) Minnesota| |38|(United-States) Mississippi| |39|(United-States) Missouri| |40|(United-States) Montana| |41|(United-States) Nebraska| |42|(United-States) Nevada| |43|(United-States) New Hampshire| |44|(United-States) New Jersey| |45|(United-States) New Mexico| |46|(United-States) New York| |47|(United-States) North Carolina| |48|(United-States) North Dakota| |49|(United-States) Ohio| |50|(United-States) Oklahoma| |51|(United-States) Oregon| |52|(United-States) Pennsylvania| |53|(United-States) Rhode Island| |54|(United-States) South Carolina| |55|(United-States) South Dakota| |56|(United-States) Tennessee| |57|(United-States) Texas| |58|(United-States) Utah| |60|(United-States) Vermont| |59|(United-States) Virginia| |61|(United-States) Washington| |62|(United-States) West Virginia| |63|(United-States) Wisconsin| |64|(United-States) Wyoming| | [optional] [default to undefined]
**sProvinceNameX** | **string** | The name of the Province in the language of the requester | [optional] [default to undefined]
**fkiCountryID** | **number** | The unique ID of the Country.  Here are some common values (Complete list must be retrieved from API):  |Value|Description| |-|-| |1|Canada| |2|United-States| | [optional] [default to undefined]
**sCountryNameX** | **string** | The name of the Country in the language of the requester | [optional] [default to undefined]
**sInscriptionnotauthenticatedOffertopurchasenumber** | **string** | The Offer to purchase number | [default to undefined]
**iInscriptionUnit** | **number** | The unit of the Inscription | [default to undefined]

## Example

```typescript
import { InscriptionnotauthenticatedListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InscriptionnotauthenticatedListElement = {
    pkiInscriptionID,
    pkiInscriptionnotauthenticatedID,
    fkiInscriptiontypeID,
    sInscriptiontypeNameX,
    fkiInscriptionbuildingtypeID,
    sInscriptionbuildingtypeNameX,
    fkiInscriptioncategoryID,
    sInscriptioncategoryNameX,
    fkiBuyercontractID,
    sBuyercontractContract,
    eInscriptionStep,
    eInscriptionType,
    sInscriptionCivicend,
    sInscriptionMLS,
    sInscriptionContract,
    dInscriptionSaleprice,
    dInscriptionRentprice,
    dtInscriptionDate,
    dtInscriptionExpirationdate,
    dtInscriptionNotarydate,
    bInscriptionInspection,
    bInscriptionIsactive,
    bInscriptionArchived,
    dtInscriptionnotauthenticatedNotaryscheduledate,
    dtInscriptionnotauthenticatedTransactiondate,
    dtInscriptionnotauthenticatedTransactiondateReal,
    bInscriptionnotauthenticatedConditional,
    bInscriptionnotauthenticatedIsactive,
    bInscriptionnotauthenticatedDraft,
    sAddressCivic,
    sAddressStreet,
    sAddressSuite,
    sAddressCity,
    sAddressZip,
    fkiProvinceID,
    sProvinceNameX,
    fkiCountryID,
    sCountryNameX,
    sInscriptionnotauthenticatedOffertopurchasenumber,
    iInscriptionUnit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
