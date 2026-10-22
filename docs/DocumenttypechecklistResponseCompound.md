# DocumenttypechecklistResponseCompound

A Documenttypechecklist Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDocumenttypechecklistID** | **number** | The unique ID of the Documenttypechecklist | [default to undefined]
**fkiDocumenttypeID** | **number** | The unique ID of the Documenttype | [default to undefined]
**sDocumenttypeNameX** | **string** | The name of the Documenttype in the language of the requester | [optional] [default to undefined]
**eDocumenttypechecklistStatus** | [**FieldEDocumenttypechecklistStatus**](FieldEDocumenttypechecklistStatus.md) |  | [default to undefined]
**tDocumenttypechecklistComment** | **string** | The comment of the Documenttypechecklist | [default to undefined]
**fkiAdjustmentID** | **number** | The unique ID of the Adjustment | [optional] [default to undefined]
**fkiAgentID** | **number** | The unique ID of the Agent. | [optional] [default to undefined]
**fkiBankaccountID** | **number** | The unique ID of the Bankaccount | [optional] [default to undefined]
**fkiBrokerID** | **number** | The unique ID of the Broker. | [optional] [default to undefined]
**fkiCommissionadvanceID** | **number** | The unique ID of the Commissionadvance | [optional] [default to undefined]
**fkiCommunicationID** | **number** | The unique ID of the Communication. | [optional] [default to undefined]
**fkiCustomerID** | **number** | The unique ID of the Customer. | [optional] [default to undefined]
**fkiCustomertemplateID** | **number** | The unique ID of the Customertemplate | [optional] [default to undefined]
**fkiDepositID** | **number** | The unique ID of the Deposit | [optional] [default to undefined]
**fkiDeposittransitchequeID** | **number** | The unique ID of the Deposittransitcheque | [optional] [default to undefined]
**fkiElectronicfundstransferID** | **number** | The unique ID of the Electronicfundstransfer | [optional] [default to undefined]
**fkiEmployeeID** | **number** | The unique ID of the Employee. | [optional] [default to undefined]
**fkiExternalbrokerID** | **number** | The unique ID of the Externalbroker. | [optional] [default to undefined]
**fkiEzcomadvanceserverID** | **number** | The unique ID of the Ezcomadvanceserver | [optional] [default to undefined]
**fkiEzcomcompanyID** | **number** | The unique ID of the Ezcomcompany | [optional] [default to undefined]
**fkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [optional] [default to undefined]
**fkiGhacqcontractID** | **number** | The unique ID of the Ghacqcontract | [optional] [default to undefined]
**fkiInscriptionID** | **number** | The unique ID of the Inscription. | [optional] [default to undefined]
**fkiInscriptiontempID** | **number** | The unique ID of the Inscriptiontemp | [optional] [default to undefined]
**fkiInscriptionnotauthenticatedID** | **number** | The unique ID of the Inscriptionnotauthenticated. | [optional] [default to undefined]
**fkiInvoiceID** | **number** | The unique ID of the Invoice. | [optional] [default to undefined]
**fkiBuyercontractID** | **number** | The unique ID of the Buyercontract | [optional] [default to undefined]
**fkiFranchisebrokerID** | **number** | The unique ID of the Franchisebroker | [optional] [default to undefined]
**fkiFranchiseagenceID** | **number** | The unique ID of the Franchiseagence | [optional] [default to undefined]
**fkiFranchiseofficeID** | **number** | The unique ID of the Franchisereoffice | [optional] [default to undefined]
**fkiFranchisefranchiseID** | **number** | The unique ID of the Franchisefranchise | [optional] [default to undefined]
**fkiFranchisecomplaintID** | **number** | The unique ID of the Franchisecomplaint | [optional] [default to undefined]
**fkiLeadID** | **number** | The unique ID of the Lead | [optional] [default to undefined]
**fkiMarketingprogramID** | **number** | The unique ID of the Marketingprogram | [optional] [default to undefined]
**fkiMarketingfollowID** | **number** | The unique ID of the Marketingfollow | [optional] [default to undefined]
**fkiNotaryID** | **number** | The unique ID of the Notary. | [optional] [default to undefined]
**fkiOfficetaxreportID** | **number** | The unique ID of the Officetaxreport | [optional] [default to undefined]
**fkiOtherincomeID** | **number** | The unique ID of the Otherincome | [optional] [default to undefined]
**fkiPaymentpreparationID** | **number** | The unique ID of the Paymentpreparation | [optional] [default to undefined]
**fkiPurchaseID** | **number** | The unique ID of the Purchase | [optional] [default to undefined]
**fkiSalaryID** | **number** | The unique ID of the Salary | [optional] [default to undefined]
**fkiSupplierID** | **number** | The unique ID of the Supplier. | [optional] [default to undefined]
**fkiTranqcontractID** | **number** | The unique ID of the Tranqcontract | [optional] [default to undefined]
**fkiTemplateID** | **number** | The unique ID of the Template | [optional] [default to undefined]

## Example

```typescript
import { DocumenttypechecklistResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DocumenttypechecklistResponseCompound = {
    pkiDocumenttypechecklistID,
    fkiDocumenttypeID,
    sDocumenttypeNameX,
    eDocumenttypechecklistStatus,
    tDocumenttypechecklistComment,
    fkiAdjustmentID,
    fkiAgentID,
    fkiBankaccountID,
    fkiBrokerID,
    fkiCommissionadvanceID,
    fkiCommunicationID,
    fkiCustomerID,
    fkiCustomertemplateID,
    fkiDepositID,
    fkiDeposittransitchequeID,
    fkiElectronicfundstransferID,
    fkiEmployeeID,
    fkiExternalbrokerID,
    fkiEzcomadvanceserverID,
    fkiEzcomcompanyID,
    fkiEzsigndocumentID,
    fkiGhacqcontractID,
    fkiInscriptionID,
    fkiInscriptiontempID,
    fkiInscriptionnotauthenticatedID,
    fkiInvoiceID,
    fkiBuyercontractID,
    fkiFranchisebrokerID,
    fkiFranchiseagenceID,
    fkiFranchiseofficeID,
    fkiFranchisefranchiseID,
    fkiFranchisecomplaintID,
    fkiLeadID,
    fkiMarketingprogramID,
    fkiMarketingfollowID,
    fkiNotaryID,
    fkiOfficetaxreportID,
    fkiOtherincomeID,
    fkiPaymentpreparationID,
    fkiPurchaseID,
    fkiSalaryID,
    fkiSupplierID,
    fkiTranqcontractID,
    fkiTemplateID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
