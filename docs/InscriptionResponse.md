# InscriptionResponse

A Inscription Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiInscriptionID** | **number** | The unique ID of the Inscription. | [default to undefined]
**fkiCompanyID** | **number** | The unique ID of the Company | [default to undefined]
**sCompanyNameX** | **string** | The Name of the Company in the language of the requester | [optional] [default to undefined]
**fkiDepartmentID** | **number** | The unique ID of the Department | [default to undefined]
**sDepartmentNameX** | **string** | The Name of the Department in the language of the requester | [optional] [default to undefined]
**fkiRealestateboardID** | **number** | The unique ID of the Realestateboard | [default to undefined]
**sRealestateboardNameX** | **string** | The name of the Realestateboard | [optional] [default to undefined]
**fkiAddressID** | **number** | The unique ID of the Address | [default to undefined]
**sAddress** | **string** | The complete address in a single line | [optional] [default to undefined]
**fkiInscriptionbuildingtypeID** | **number** | The unique ID of the Inscriptionbuildingtype | [default to undefined]
**sInscriptionbuildingtypeNameX** | **string** | The name of the Inscriptionbuildingtype in the language of the requester | [optional] [default to undefined]
**fkiInscriptiontypeID** | **number** | The unique ID of the Inscriptiontype | [default to undefined]
**sInscriptiontypeNameX** | **string** | The name of the Inscriptiontype in the language of the requester | [optional] [default to undefined]
**fkiInscriptioncategoryID** | **number** | The unique ID of the Inscriptioncategory | [default to undefined]
**sInscriptioncategoryNameX** | **string** | The name of the Inscriptioncategory in the language of the requester | [optional] [default to undefined]
**eInscriptionStep** | [**FieldEInscriptionStep**](FieldEInscriptionStep.md) |  | [default to undefined]
**eInscriptionResidenceType** | [**FieldEInscriptionResidenceType**](FieldEInscriptionResidenceType.md) |  | [default to undefined]
**sInscriptionCivicend** | **string** | The civicend of the Inscription | [default to undefined]
**sInscriptionMLS** | **string** | The mls of the Inscription | [default to undefined]
**sInscriptionContract** | **string** | The sale contract number | [default to undefined]
**iInscriptionSellerdeclaration** | **number** | The sellerdeclaration of the Inscription | [default to undefined]
**eInscriptionType** | [**FieldEInscriptionType**](FieldEInscriptionType.md) |  | [default to undefined]
**dInscriptionInitialsaleprice** | **string** | The initialsaleprice of the Inscription | [default to undefined]
**dInscriptionSaleprice** | **string** | The saleprice of the Inscription | [default to undefined]
**dInscriptionRentprice** | **string** | The rentprice of the Inscription | [default to undefined]
**eInscriptionRemunerationtype** | [**FieldEInscriptionRemunerationtype**](FieldEInscriptionRemunerationtype.md) |  | [default to undefined]
**eInscriptionRemunerationinscriptorsellertype** | [**FieldEInscriptionRemunerationinscriptorsellertype**](FieldEInscriptionRemunerationinscriptorsellertype.md) |  | [default to undefined]
**eInscriptionRemunerationreferencetype** | [**FieldEInscriptionRemunerationreferencetype**](FieldEInscriptionRemunerationreferencetype.md) |  | [default to undefined]
**eInscriptionRemunerationtotaltype** | [**FieldEInscriptionRemunerationtotaltype**](FieldEInscriptionRemunerationtotaltype.md) |  | [default to undefined]
**dInscriptionRemuneration** | **string** | The remuneration of the Inscription | [default to undefined]
**dInscriptionRemunerationinscriptorseller** | **string** | The remunerationinscriptorseller of the Inscription | [default to undefined]
**dInscriptionRemunerationreference** | **string** | The remunerationreference of the Inscription | [default to undefined]
**dInscriptionRemunerationtotal** | **string** | The remunerationtotal of the Inscription | [default to undefined]
**dInscriptionMortgagesold** | **string** | The mortgagesold of the Inscription | [default to undefined]
**dtInscriptionDate** | **string** | The date of the Inscription | [default to undefined]
**dtInscriptionCancellationdate** | **string** | The cancellationdate of the Inscription | [default to undefined]
**dtInscriptionInitialexpirationdate** | **string** | The initialexpirationdate of the Inscription | [default to undefined]
**dtInscriptionExpirationdate** | **string** | The expirationdate of the Inscription | [default to undefined]
**dtInscriptionNotarydate** | **string** | The notarydate of the Inscription | [default to undefined]
**dtInscriptionNotaryentereddate** | **string** | The notaryentereddate of the Inscription | [default to undefined]
**tInscriptionCadastre** | **string** | The cadastre of the Inscription | [default to undefined]
**bInscriptionReference** | **boolean** | Whether if it\&#39;s an reference | [default to undefined]
**bInscriptionInspection** | **boolean** | Whether the inscription can be acces by an inspector | [default to undefined]
**bInscriptionIsactive** | **boolean** | Whether the inscription is active or not | [default to undefined]
**tInscriptionChecklistnote** | **string** | The checklistnote of the Inscription | [default to undefined]
**bInscriptionNew** | **boolean** | Whether if it\&#39;s an new | [default to undefined]
**bInscriptionHomeowner** | **boolean** | Whether if it\&#39;s an homeowner | [default to undefined]
**bInscriptionArchived** | **boolean** | Whether the inscription is archived or not | [default to undefined]
**bInscriptionLitigation** | **boolean** | Whether if it\&#39;s an litigation | [default to undefined]
**bInscriptionRepossession** | **boolean** | Whether if it\&#39;s an repossession | [default to undefined]
**bInscriptionIssolicitation** | **boolean** | Whether if it\&#39;s an issolicitation | [default to undefined]
**bInscriptionSalebyowner** | **boolean** | Whether if it\&#39;s an salebyowner | [default to undefined]
**bInscriptionSoldwithoutlegalwarranty** | **boolean** | Whether if it\&#39;s an soldwithoutlegalwarranty | [default to undefined]
**iInscriptionConstructionyear** | **number** | The constructionyear of the Inscription | [default to undefined]
**iInscriptionUnit** | **number** | The unit of the Inscription | [default to undefined]

## Example

```typescript
import { InscriptionResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InscriptionResponse = {
    pkiInscriptionID,
    fkiCompanyID,
    sCompanyNameX,
    fkiDepartmentID,
    sDepartmentNameX,
    fkiRealestateboardID,
    sRealestateboardNameX,
    fkiAddressID,
    sAddress,
    fkiInscriptionbuildingtypeID,
    sInscriptionbuildingtypeNameX,
    fkiInscriptiontypeID,
    sInscriptiontypeNameX,
    fkiInscriptioncategoryID,
    sInscriptioncategoryNameX,
    eInscriptionStep,
    eInscriptionResidenceType,
    sInscriptionCivicend,
    sInscriptionMLS,
    sInscriptionContract,
    iInscriptionSellerdeclaration,
    eInscriptionType,
    dInscriptionInitialsaleprice,
    dInscriptionSaleprice,
    dInscriptionRentprice,
    eInscriptionRemunerationtype,
    eInscriptionRemunerationinscriptorsellertype,
    eInscriptionRemunerationreferencetype,
    eInscriptionRemunerationtotaltype,
    dInscriptionRemuneration,
    dInscriptionRemunerationinscriptorseller,
    dInscriptionRemunerationreference,
    dInscriptionRemunerationtotal,
    dInscriptionMortgagesold,
    dtInscriptionDate,
    dtInscriptionCancellationdate,
    dtInscriptionInitialexpirationdate,
    dtInscriptionExpirationdate,
    dtInscriptionNotarydate,
    dtInscriptionNotaryentereddate,
    tInscriptionCadastre,
    bInscriptionReference,
    bInscriptionInspection,
    bInscriptionIsactive,
    tInscriptionChecklistnote,
    bInscriptionNew,
    bInscriptionHomeowner,
    bInscriptionArchived,
    bInscriptionLitigation,
    bInscriptionRepossession,
    bInscriptionIssolicitation,
    bInscriptionSalebyowner,
    bInscriptionSoldwithoutlegalwarranty,
    iInscriptionConstructionyear,
    iInscriptionUnit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
