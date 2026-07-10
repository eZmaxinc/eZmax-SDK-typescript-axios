# InscriptionnotauthenticatedResponseCompound

A Inscriptionnotauthenticated Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiInscriptionnotauthenticatedID** | **number** | The unique ID of the Inscriptionnotauthenticated. | [default to undefined]
**fkiCompanyID** | **number** | The unique ID of the Company | [default to undefined]
**sCompanyNameX** | **string** | The Name of the Company in the language of the requester | [optional] [default to undefined]
**fkiInscriptionID** | **number** | The unique ID of the Inscription. | [default to undefined]
**fkiDepartmentID** | **number** | The unique ID of the Department | [default to undefined]
**sDepartmentNameX** | **string** | The Name of the Department in the language of the requester | [optional] [default to undefined]
**fkiFinancialinstitutionID** | **number** | The unique ID of the Financialinstitution | [default to undefined]
**sFinancialinstitutionNameX** | **string** | The name of the Financialinstitution in the language of the requester | [optional] [default to undefined]
**fkiBuyercontractID** | **number** | The unique ID of the Buyercontract | [default to undefined]
**sBuyercontractContract** | **string** | The number of the Buyercontract | [optional] [default to undefined]
**fkiMortgagesupplierID** | **number** | The unique ID of the Mortgagesupplier | [default to undefined]
**sMortgagesupplierNameX** | **string** | The name of the Mortagesupplier in the language of the requester | [optional] [default to undefined]
**fkiTaxassignmentID** | **number** | The unique ID of the Taxassignment.  Valid values:  |Value|Description| |-|-| |1|No tax| |2|GST| |3|HST (ON)| |4|HST (NB)| |5|HST (NS)| |6|HST (NL)| |7|HST (PE)| |8|GST + QST (QC)| |9|GST + QST (QC) Non-Recoverable| |10|GST + PST (BC)| |11|GST + PST (SK)| |12|GST + RST (MB)| |13|GST + PST (BC) Non-Recoverable| |14|GST + PST (SK) Non-Recoverable| |15|GST + RST (MB) Non-Recoverable| | [default to undefined]
**sTaxassignmentDescriptionX** | **string** | The description of the Taxassignment  in the language of the requester | [optional] [default to undefined]
**dtInscriptionnotauthenticatedTransactiondate** | **string** | The transactiondate of the Inscriptionnotauthenticated | [default to undefined]
**dtInscriptionnotauthenticatedTransactiondateReal** | **string** | The transactiondatereal of the Inscriptionnotauthenticated | [default to undefined]
**dtInscriptionnotauthenticatedDepositdate** | **string** | The depositdate of the Inscriptionnotauthenticated | [default to undefined]
**eInscriptionnotauthenticatedType** | [**FieldEInscriptionnotauthenticatedType**](FieldEInscriptionnotauthenticatedType.md) |  | [default to undefined]
**dInscriptionnotauthenticatedMortgageloan** | **string** | The mortgageloan of the Inscriptionnotauthenticated | [default to undefined]
**etInscriptionnotauthenticatedMortgagetype** | [**FieldEtInscriptionnotauthenticatedMortgagetype**](FieldEtInscriptionnotauthenticatedMortgagetype.md) |  | [default to undefined]
**dInscriptionnotauthenticatedTransactionprice** | **string** | The transactionprice of the Inscriptionnotauthenticated | [default to undefined]
**eInscriptionnotauthenticatedRemunerationtype** | [**FieldEInscriptionnotauthenticatedRemunerationtype**](FieldEInscriptionnotauthenticatedRemunerationtype.md) |  | [default to undefined]
**dInscriptionnotauthenticatedRemuneration** | **string** | The remuneration of the Inscriptionnotauthenticated | [default to undefined]
**dInscriptionnotauthenticatedRemunerationsubtotal** | **string** | The remunerationsubtotal of the Inscriptionnotauthenticated | [default to undefined]
**dInscriptionnotauthenticatedRemunerationtotal** | **string** | The remunerationtotal of the Inscriptionnotauthenticated | [default to undefined]
**dtInscriptionnotauthenticatedCancellationdate** | **string** | The cancellationdate of the Inscriptionnotauthenticated | [default to undefined]
**dtInscriptionnotauthenticatedPossessiondate** | **string** | The possessiondate of the Inscriptionnotauthenticated | [default to undefined]
**sInscriptionnotauthenticatedOffertopurchasenumber** | **string** | The Offer to purchase number | [default to undefined]
**dtInscriptionnotauthenticatedNotaryscheduledate** | **string** | The notaryscheduledate of the Inscriptionnotauthenticated | [default to undefined]
**dtInscriptionnotauthenticatedFinancingscheduledate** | **string** | The financingscheduledate of the Inscriptionnotauthenticated | [default to undefined]
**bInscriptionnotauthenticatedConditional** | **boolean** | Whether the inscriptionnotauthenticated is conditional | [default to undefined]
**bInscriptionnotauthenticatedMortgageisreferenced** | **boolean** | Whether if it\&#39;s an mortgageisreferenced | [default to undefined]
**bInscriptionnotauthenticatedHomeowner** | **boolean** | Whether if it\&#39;s an homeowner | [default to undefined]
**tInscriptionnotauthenticatedConditions** | **string** | The conditions of the Inscriptionnotauthenticated | [default to undefined]
**dtInscriptionnotauthenticatedConditiondeadlinedate** | **string** | The conditiondeadlinedate of the Inscriptionnotauthenticated | [default to undefined]
**iInscriptionnotauthenticatedOrder** | **number** | The order of the Inscriptionnotauthenticated | [default to undefined]
**bInscriptionnotauthenticatedIsactive** | **boolean** | Whether the inscriptionnotauthenticated is active or not | [default to undefined]
**eInscriptionnotauthenticatedResidenceType** | [**FieldEInscriptionnotauthenticatedResidenceType**](FieldEInscriptionnotauthenticatedResidenceType.md) |  | [default to undefined]
**tInscriptionnotauthenticatedChecklistnote** | **string** | The checklistnote of the Inscriptionnotauthenticated | [default to undefined]
**dInscriptionnotauthenticatedSelleronlyretribution** | **string** | The selleronlyretribution of the Inscriptionnotauthenticated | [default to undefined]
**bInscriptionnotauthenticatedDraft** | **boolean** | Whether the inscriptionnotauthenticated is a draft or not | [default to undefined]

## Example

```typescript
import { InscriptionnotauthenticatedResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InscriptionnotauthenticatedResponseCompound = {
    pkiInscriptionnotauthenticatedID,
    fkiCompanyID,
    sCompanyNameX,
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
