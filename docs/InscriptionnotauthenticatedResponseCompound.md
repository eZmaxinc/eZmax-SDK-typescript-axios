# InscriptionnotauthenticatedResponseCompound

A Inscriptionnotauthenticated Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiInscriptionnotauthenticatedID** | **number** | The unique ID of the Inscriptionnotauthenticated. | [default to undefined]
**fkiInscriptionID** | **number** | The unique ID of the Inscription. | [default to undefined]
**fkiDepartmentID** | **number** | The unique ID of the Department | [optional] [default to undefined]
**sDepartmentNameX** | **string** | The Name of the Department in the language of the requester | [optional] [default to undefined]
**fkiFinancialinstitutionID** | **number** | The unique ID of the Financialinstitution | [optional] [default to undefined]
**sFinancialinstitutionNameX** | **string** | The name of the Financialinstitution in the language of the requester | [optional] [default to undefined]
**fkiBuyercontractID** | **number** | The unique ID of the Buyercontract | [optional] [default to undefined]
**sBuyercontractContract** | **string** | The number of the Buyercontract | [optional] [default to undefined]
**fkiMortgagesupplierID** | **number** | The unique ID of the Mortgagesupplier | [optional] [default to undefined]
**sMortgagesupplierNameX** | **string** | The name of the Mortagesupplier in the language of the requester | [optional] [default to undefined]
**fkiTaxassignmentID** | **number** | The unique ID of the Taxassignment.  Valid values:  |Value|Description| |-|-| |1|No tax| |2|GST| |3|HST (ON)| |4|HST (NB)| |5|HST (NS)| |6|HST (NL)| |7|HST (PE)| |8|GST + QST (QC)| |9|GST + QST (QC) Non-Recoverable| |10|GST + PST (BC)| |11|GST + PST (SK)| |12|GST + RST (MB)| |13|GST + PST (BC) Non-Recoverable| |14|GST + PST (SK) Non-Recoverable| |15|GST + RST (MB) Non-Recoverable| | [default to undefined]
**sTaxassignmentDescriptionX** | **string** | The description of the Taxassignment  in the language of the requester | [optional] [default to undefined]
**dtInscriptionnotauthenticatedTransactiondate** | **string** | The transaction date of the Inscriptionnotauthenticated | [optional] [default to undefined]
**dtInscriptionnotauthenticatedTransactiondateReal** | **string** | The real transactiondate of the Inscriptionnotauthenticated | [optional] [default to undefined]
**dtInscriptionnotauthenticatedDepositdate** | **string** | The deposit date of the Inscriptionnotauthenticated | [optional] [default to undefined]
**eInscriptionnotauthenticatedType** | [**FieldEInscriptionnotauthenticatedType**](FieldEInscriptionnotauthenticatedType.md) |  | [default to undefined]
**dInscriptionnotauthenticatedMortgageloan** | **string** | The amount of the mortgage loan of the Inscriptionnotauthenticated | [default to undefined]
**etInscriptionnotauthenticatedMortgagetype** | [**FieldEtInscriptionnotauthenticatedMortgagetype**](FieldEtInscriptionnotauthenticatedMortgagetype.md) |  | [default to undefined]
**dInscriptionnotauthenticatedTransactionprice** | **string** | The transaction price of the Inscriptionnotauthenticated | [default to undefined]
**eInscriptionnotauthenticatedRemunerationtype** | [**FieldEInscriptionnotauthenticatedRemunerationtype**](FieldEInscriptionnotauthenticatedRemunerationtype.md) |  | [default to undefined]
**dInscriptionnotauthenticatedRemuneration** | **string** | The amount for the remuneration of the Inscriptionnotauthenticated | [default to undefined]
**dInscriptionnotauthenticatedRemunerationsubtotal** | **string** | The subtotal for the remuneration of the Inscriptionnotauthenticated | [default to undefined]
**dInscriptionnotauthenticatedRemunerationtotal** | **string** | The total for the remuneration of the Inscriptionnotauthenticated | [default to undefined]
**dtInscriptionnotauthenticatedCancellationdate** | **string** | The cancellation date of the Inscriptionnotauthenticated | [optional] [default to undefined]
**dtInscriptionnotauthenticatedPossessiondate** | **string** | The possession date of the Inscriptionnotauthenticated | [optional] [default to undefined]
**sInscriptionnotauthenticatedOffertopurchasenumber** | **string** | The offer to purchase number of the Inscriptionnotauthenticated | [default to undefined]
**dtInscriptionnotauthenticatedNotaryscheduledate** | **string** | The notary schedule date of the Inscriptionnotauthenticated | [optional] [default to undefined]
**dtInscriptionnotauthenticatedFinancingscheduledate** | **string** | The financing schedule date of the Inscriptionnotauthenticated | [optional] [default to undefined]
**bInscriptionnotauthenticatedConditional** | **boolean** | Whether the inscriptionnotauthenticated is conditional | [default to undefined]
**bInscriptionnotauthenticatedMortgageisreferenced** | **boolean** | Whether if the mortgage is referenced | [default to undefined]
**bInscriptionnotauthenticatedHomeowner** | **boolean** | Whether if it\&#39;s an home owner | [default to undefined]
**tInscriptionnotauthenticatedConditions** | **string** | The conditions of the Inscriptionnotauthenticated | [default to undefined]
**dtInscriptionnotauthenticatedConditiondeadlinedate** | **string** | The condition deadline date of the Inscriptionnotauthenticated | [optional] [default to undefined]
**iInscriptionnotauthenticatedOrder** | **number** | The order of the Inscriptionnotauthenticated | [default to undefined]
**bInscriptionnotauthenticatedIsactive** | **boolean** | Whether the inscriptionnotauthenticated is active or not | [default to undefined]
**eInscriptionnotauthenticatedResidenceType** | [**FieldEInscriptionnotauthenticatedResidenceType**](FieldEInscriptionnotauthenticatedResidenceType.md) |  | [default to undefined]
**tInscriptionnotauthenticatedChecklistnote** | **string** | The checklist note of the Inscriptionnotauthenticated | [default to undefined]
**dInscriptionnotauthenticatedSelleronlyretribution** | **string** | The amount retribution for the seller only of the Inscriptionnotauthenticated | [default to undefined]
**bInscriptionnotauthenticatedDraft** | **boolean** | Whether the Inscriptionnotauthenticated is a draft or not | [default to undefined]

## Example

```typescript
import { InscriptionnotauthenticatedResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InscriptionnotauthenticatedResponseCompound = {
    pkiInscriptionnotauthenticatedID,
    fkiInscriptionID,
    fkiDepartmentID,
    sDepartmentNameX,
    fkiFinancialinstitutionID,
    sFinancialinstitutionNameX,
    fkiBuyercontractID,
    sBuyercontractContract,
    fkiMortgagesupplierID,
    sMortgagesupplierNameX,
    fkiTaxassignmentID,
    sTaxassignmentDescriptionX,
    dtInscriptionnotauthenticatedTransactiondate,
    dtInscriptionnotauthenticatedTransactiondateReal,
    dtInscriptionnotauthenticatedDepositdate,
    eInscriptionnotauthenticatedType,
    dInscriptionnotauthenticatedMortgageloan,
    etInscriptionnotauthenticatedMortgagetype,
    dInscriptionnotauthenticatedTransactionprice,
    eInscriptionnotauthenticatedRemunerationtype,
    dInscriptionnotauthenticatedRemuneration,
    dInscriptionnotauthenticatedRemunerationsubtotal,
    dInscriptionnotauthenticatedRemunerationtotal,
    dtInscriptionnotauthenticatedCancellationdate,
    dtInscriptionnotauthenticatedPossessiondate,
    sInscriptionnotauthenticatedOffertopurchasenumber,
    dtInscriptionnotauthenticatedNotaryscheduledate,
    dtInscriptionnotauthenticatedFinancingscheduledate,
    bInscriptionnotauthenticatedConditional,
    bInscriptionnotauthenticatedMortgageisreferenced,
    bInscriptionnotauthenticatedHomeowner,
    tInscriptionnotauthenticatedConditions,
    dtInscriptionnotauthenticatedConditiondeadlinedate,
    iInscriptionnotauthenticatedOrder,
    bInscriptionnotauthenticatedIsactive,
    eInscriptionnotauthenticatedResidenceType,
    tInscriptionnotauthenticatedChecklistnote,
    dInscriptionnotauthenticatedSelleronlyretribution,
    bInscriptionnotauthenticatedDraft,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
