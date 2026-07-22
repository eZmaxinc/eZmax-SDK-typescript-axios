# InscriptionResponseCompound

A Inscription Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiInscriptionID** | **number** | The unique ID of the Inscription. | [default to undefined]
**fkiDepartmentID** | **number** | The unique ID of the Department | [optional] [default to undefined]
**sDepartmentNameX** | **string** | The Name of the Department in the language of the requester | [optional] [default to undefined]
**fkiRealestateboardID** | **number** | The unique ID of the Realestateboard | [default to undefined]
**sRealestateboardNameX** | **string** | The name of the Realestateboard | [optional] [default to undefined]
**fkiAddressID** | **number** | The unique ID of the Address | [default to undefined]
**objAddress** | [**AddressResponseCompound**](AddressResponseCompound.md) |  | [optional] [default to undefined]
**fkiInscriptionbuildingtypeID** | **number** | The unique ID of the Inscriptionbuildingtype | [default to undefined]
**sInscriptionbuildingtypeNameX** | **string** | The name of the Inscriptionbuildingtype in the language of the requester | [optional] [default to undefined]
**fkiInscriptiontypeID** | **number** | The unique ID of the Inscriptiontype | [default to undefined]
**sInscriptiontypeNameX** | **string** | The name of the Inscriptiontype in the language of the requester | [optional] [default to undefined]
**fkiInscriptioncategoryID** | **number** | The unique ID of the Inscriptioncategory | [default to undefined]
**sInscriptioncategoryNameX** | **string** | The name of the Inscriptioncategory in the language of the requester | [optional] [default to undefined]
**eInscriptionStep** | [**FieldEInscriptionStep**](FieldEInscriptionStep.md) |  | [default to undefined]
**eInscriptionResidenceType** | [**FieldEInscriptionResidenceType**](FieldEInscriptionResidenceType.md) |  | [default to undefined]
**sInscriptionCivicend** | **string** | The address civic end of the Inscription | [default to undefined]
**sInscriptionMLS** | **string** | The mls of the Inscription | [optional] [default to undefined]
**sInscriptionContract** | **string** | The sale contract number | [default to undefined]
**iInscriptionSellerdeclaration** | **number** | The seller declaration number of the Inscription | [default to undefined]
**eInscriptionType** | [**FieldEInscriptionType**](FieldEInscriptionType.md) |  | [default to undefined]
**dInscriptionInitialsaleprice** | **string** | The initial sale price of the Inscription | [default to undefined]
**dInscriptionSaleprice** | **string** | The saleprice of the Inscription | [default to undefined]
**dInscriptionRentprice** | **string** | The rent price of the Inscription | [default to undefined]
**eInscriptionRemunerationtype** | [**FieldEInscriptionRemunerationtype**](FieldEInscriptionRemunerationtype.md) |  | [default to undefined]
**eInscriptionRemunerationinscriptorsellertype** | [**FieldEInscriptionRemunerationinscriptorsellertype**](FieldEInscriptionRemunerationinscriptorsellertype.md) |  | [default to undefined]
**eInscriptionRemunerationreferencetype** | [**FieldEInscriptionRemunerationreferencetype**](FieldEInscriptionRemunerationreferencetype.md) |  | [default to undefined]
**eInscriptionRemunerationtotaltype** | [**FieldEInscriptionRemunerationtotaltype**](FieldEInscriptionRemunerationtotaltype.md) |  | [default to undefined]
**dInscriptionRemuneration** | **string** | The remuneration amount of the Inscription | [default to undefined]
**dInscriptionRemunerationinscriptorseller** | **string** | The remuneration amount for the inscriptor or seller of the Inscription | [default to undefined]
**dInscriptionRemunerationreference** | **string** | The remuneration amount for the reference of the Inscription | [default to undefined]
**dInscriptionRemunerationtotal** | **string** | The remuneration amount total of the Inscription | [default to undefined]
**dInscriptionMortgagesold** | **string** | The balande for the mortgage of the Inscription | [default to undefined]
**dtInscriptionDate** | **string** | The date of the Inscription | [optional] [default to undefined]
**dtInscriptionCancellationdate** | **string** | The cancellation date of the Inscription | [optional] [default to undefined]
**dtInscriptionInitialexpirationdate** | **string** | The initial expiration date of the Inscription | [optional] [default to undefined]
**dtInscriptionExpirationdate** | **string** | The expiration date of the Inscription | [optional] [default to undefined]
**dtInscriptionNotarydate** | **string** | The notary date of the Inscription | [optional] [default to undefined]
**dtInscriptionNotaryentereddate** | **string** | The notary entered date of the Inscription | [optional] [default to undefined]
**tInscriptionCadastre** | **string** | The cadastre of the Inscription | [default to undefined]
**bInscriptionReference** | **boolean** | Whether if it\&#39;s an reference | [default to undefined]
**bInscriptionInspection** | **boolean** | Whether the inscription can be acces by an inspector | [default to undefined]
**bInscriptionIsactive** | **boolean** | Whether the inscription is active or not | [default to undefined]
**tInscriptionChecklistnote** | **string** | The checklist note of the Inscription | [default to undefined]
**bInscriptionNew** | **boolean** | Whether if it\&#39;s an new | [default to undefined]
**bInscriptionHomeowner** | **boolean** | Whether if it\&#39;s an homeowner | [default to undefined]
**bInscriptionArchived** | **boolean** | Whether the inscription is archived or not | [default to undefined]
**bInscriptionLitigation** | **boolean** | Whether if it\&#39;s an litigation | [default to undefined]
**bInscriptionRepossession** | **boolean** | Whether if it\&#39;s an repossession | [default to undefined]
**bInscriptionIssolicitation** | **boolean** | Whether if it\&#39;s a solicitation | [default to undefined]
**bInscriptionSalebyowner** | **boolean** | Whether if it\&#39;s a sale by the owner | [default to undefined]
**bInscriptionSoldwithoutlegalwarranty** | **boolean** | Whether if it\&#39;s sold without the legal warranty | [default to undefined]
**iInscriptionConstructionyear** | **number** | The construction year of the Inscription | [default to undefined]
**iInscriptionUnit** | **number** | The number of unit for the Inscription | [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [optional] [default to undefined]

## Example

```typescript
import { InscriptionResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InscriptionResponseCompound = {
    pkiInscriptionID,
    fkiDepartmentID,
    sDepartmentNameX,
    fkiRealestateboardID,
    sRealestateboardNameX,
    fkiAddressID,
    objAddress,
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
    objAudit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
