/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { AttachmentResponse } from './attachment-response';
// May contain unused imports in some cases
// @ts-ignore
import { AttachmentResponseCompound } from './attachment-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEAttachmentDocumenttype } from './field-eattachment-documenttype';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEAttachmentPrivacy } from './field-eattachment-privacy';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEAttachmentType } from './field-eattachment-type';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEAttachmentVerified } from './field-eattachment-verified';

/**
 * @type CustomAttachmentResponse
 * A Custom Attachment Object
 * @export
 */
/*export type CustomAttachmentResponse = AttachmentResponse;*/
export interface CustomAttachmentResponse {
    /**
     * The unique ID of the Attachment.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    pkiAttachmentID:number 
    /**
     * The unique ID of the Computer
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiComputerID?:number 
    /**
     * The unique ID of the Adjustment
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiAdjustmentID?:number 
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiAgentID?:number 
    /**
     * The unique ID of the Bankaccount
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiBankaccountID?:number 
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiBrokerID?:number 
    /**
     * The unique ID of the Commissionadvance
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiCommissionadvanceID?:number 
    /**
     * The unique ID of the Communication.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiCommunicationID?:number 
    /**
     * The unique ID of the Customer.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiCustomerID?:number 
    /**
     * The unique ID of the Customertemplate
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiCustomertemplateID?:number 
    /**
     * The unique ID of the Deposit
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiDepositID?:number 
    /**
     * The unique ID of the Deposittransitcheque
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiDeposittransitchequeID?:number 
    /**
     * The unique ID of the Electronicfundstransfer
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiElectronicfundstransferID?:number 
    /**
     * The unique ID of the Employee.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiEmployeeID?:number 
    /**
     * The unique ID of the Externalbroker.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiExternalbrokerID?:number 
    /**
     * The unique ID of the Ezcomadvanceserver
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiEzcomadvanceserverID?:number 
    /**
     * The unique ID of the Ezcomcompany
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiEzcomcompanyID?:number 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiEzsigndocumentID?:number 
    /**
     * The unique ID of the Ghacqcontract
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiGhacqcontractID?:number 
    /**
     * The unique ID of the Inscription.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiInscriptionID?:number 
    /**
     * The unique ID of the Inscriptiontemp
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiInscriptiontempID?:number 
    /**
     * The unique ID of the Inscriptionnotauthenticated.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiInscriptionnotauthenticatedID?:number 
    /**
     * The unique ID of the Invoice.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiInvoiceID?:number 
    /**
     * The unique ID of the Buyercontract
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiBuyercontractID?:number 
    /**
     * The unique ID of the Franchisebroker
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiFranchisebrokerID?:number 
    /**
     * The unique ID of the Franchiseagence
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiFranchiseagenceID?:number 
    /**
     * The unique ID of the Franchisereoffice
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiFranchiseofficeID?:number 
    /**
     * The unique ID of the Franchisefranchise
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiFranchisefranchiseID?:number 
    /**
     * The unique ID of the Franchisecomplaint
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiFranchisecomplaintID?:number 
    /**
     * The unique ID of the Lead
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiLeadID?:number 
    /**
     * The unique ID of the Marketingprogram
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiMarketingprogramID?:number 
    /**
     * The unique ID of the Marketingfollow
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiMarketingfollowID?:number 
    /**
     * The unique ID of the Notary.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiNotaryID?:number 
    /**
     * The unique ID of the Officetaxreport
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiOfficetaxreportID?:number 
    /**
     * The unique ID of the Otherincome
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiOtherincomeID?:number 
    /**
     * The unique ID of the Paymentpreparation
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiPaymentpreparationID?:number 
    /**
     * The unique ID of the Purchase
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiPurchaseID?:number 
    /**
     * The unique ID of the Salary
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiSalaryID?:number 
    /**
     * The unique ID of the Supplier.
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiSupplierID?:number 
    /**
     * The unique ID of the Tranqcontract
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiTranqcontractID?:number 
    /**
     * The unique ID of the Template
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiTemplateID?:number 
    /**
     * The unique ID of the Inscriptionchecklist
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiInscriptionchecklistID?:number 
    /**
     * The unique ID of the Folder
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiFolderID?:number 
    /**
     * The unique ID of the Rejectedoffertopurchase
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiRejectedoffertopurchaseID?:number 
    /**
     * The unique ID of the Disclosure
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiDisclosureID?:number 
    /**
     * The unique ID of the Reconciliation
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiReconciliationID?:number 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiEzsigndocumentIDReference?:number 
    /**
     * 
     * @type {FieldEAttachmentDocumenttype}
     * @memberof CustomAttachmentResponse
     */
    eAttachmentDocumenttype:FieldEAttachmentDocumenttype 
    /**
     * The name of the Attachment
     * @type {string}
     * @memberof CustomAttachmentResponse
     */
    sAttachmentName:string 
    /**
     * 
     * @type {FieldEAttachmentPrivacy}
     * @memberof CustomAttachmentResponse
     */
    eAttachmentPrivacy:FieldEAttachmentPrivacy 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiUserIDSpecific?:number 
    /**
     * 
     * @type {FieldEAttachmentType}
     * @memberof CustomAttachmentResponse
     */
    eAttachmentType:FieldEAttachmentType 
    /**
     * The size of the Attachment
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    iAttachmentSize:number 
    /**
     * The edmmoduleflag of the Attachment
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    iAttachmentEDMmoduleflag?:number 
    /**
     * The md5 of the Attachment
     * @type {string}
     * @memberof CustomAttachmentResponse
     */
    sAttachmentMD5:string 
    /**
     * Whether if it\'s deleted
     * @type {boolean}
     * @memberof CustomAttachmentResponse
     */
    bAttachmentDeleted:boolean 
    /**
     * Whether if it\'s valid
     * @type {boolean}
     * @memberof CustomAttachmentResponse
     */
    bAttachmentValid:boolean 
    /**
     * 
     * @type {FieldEAttachmentVerified}
     * @memberof CustomAttachmentResponse
     */
    eAttachmentVerified:FieldEAttachmentVerified 
    /**
     * The rejectioncomment of the Attachment
     * @type {string}
     * @memberof CustomAttachmentResponse
     */
    tAttachmentRejectioncomment?:string 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CustomAttachmentResponse
     */
    fkiUserIDOwner?:number 
    /**
     * 
     * @type {CommonAudit}
     * @memberof CustomAttachmentResponse
     */
    objAudit?:CommonAudit 
    /**
     * 
     * @type {AttachmentResponseCompound}
     * @memberof CustomAttachmentResponse
     */
    objAttachmentProof?:AttachmentResponseCompound 
    /**
     * 
     * @type {AttachmentResponseCompound}
     * @memberof CustomAttachmentResponse
     */
    objAttachmentProofdocument?:AttachmentResponseCompound 
    /**
     * 
     * @type {Array<AttachmentResponseCompound>}
     * @memberof CustomAttachmentResponse
     */
    a_objAttachmentAttachment?:Array<AttachmentResponseCompound> 
    /**
     * 
     * @type {Array<AttachmentResponseCompound>}
     * @memberof CustomAttachmentResponse
     */
    a_objAttachmentVersion?:Array<AttachmentResponseCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { DataObjectAttachmentResponseCompound } from './'
// @ts-ignore
import { DataObjectAttachmentResponseCompound } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectAttachmentResponseCompound } from './'
// @ts-ignore
import { ValidationObjectAttachmentResponseCompound } from './'

/**
 * @export 
 * A CustomAttachmentResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomAttachmentResponse
 */
export class DataObjectCustomAttachmentResponse {
    pkiAttachmentID:number = 0
    fkiComputerID?:number = undefined
    fkiAdjustmentID?:number = undefined
    fkiAgentID?:number = undefined
    fkiBankaccountID?:number = undefined
    fkiBrokerID?:number = undefined
    fkiCommissionadvanceID?:number = undefined
    fkiCommunicationID?:number = undefined
    fkiCustomerID?:number = undefined
    fkiCustomertemplateID?:number = undefined
    fkiDepositID?:number = undefined
    fkiDeposittransitchequeID?:number = undefined
    fkiElectronicfundstransferID?:number = undefined
    fkiEmployeeID?:number = undefined
    fkiExternalbrokerID?:number = undefined
    fkiEzcomadvanceserverID?:number = undefined
    fkiEzcomcompanyID?:number = undefined
    fkiEzsigndocumentID?:number = undefined
    fkiGhacqcontractID?:number = undefined
    fkiInscriptionID?:number = undefined
    fkiInscriptiontempID?:number = undefined
    fkiInscriptionnotauthenticatedID?:number = undefined
    fkiInvoiceID?:number = undefined
    fkiBuyercontractID?:number = undefined
    fkiFranchisebrokerID?:number = undefined
    fkiFranchiseagenceID?:number = undefined
    fkiFranchiseofficeID?:number = undefined
    fkiFranchisefranchiseID?:number = undefined
    fkiFranchisecomplaintID?:number = undefined
    fkiLeadID?:number = undefined
    fkiMarketingprogramID?:number = undefined
    fkiMarketingfollowID?:number = undefined
    fkiNotaryID?:number = undefined
    fkiOfficetaxreportID?:number = undefined
    fkiOtherincomeID?:number = undefined
    fkiPaymentpreparationID?:number = undefined
    fkiPurchaseID?:number = undefined
    fkiSalaryID?:number = undefined
    fkiSupplierID?:number = undefined
    fkiTranqcontractID?:number = undefined
    fkiTemplateID?:number = undefined
    fkiInscriptionchecklistID?:number = undefined
    fkiFolderID?:number = undefined
    fkiRejectedoffertopurchaseID?:number = undefined
    fkiDisclosureID?:number = undefined
    fkiReconciliationID?:number = undefined
    fkiEzsigndocumentIDReference?:number = undefined
    eAttachmentDocumenttype:FieldEAttachmentDocumenttype = 'Adjustment'
    sAttachmentName:string = ''
    eAttachmentPrivacy:FieldEAttachmentPrivacy = 'All'
    fkiUserIDSpecific?:number = undefined
    eAttachmentType:FieldEAttachmentType = 'Other'
    iAttachmentSize:number = 0
    iAttachmentEDMmoduleflag?:number = undefined
    sAttachmentMD5:string = ''
    bAttachmentDeleted:boolean = false
    bAttachmentValid:boolean = false
    eAttachmentVerified:FieldEAttachmentVerified = 'No'
    tAttachmentRejectioncomment?:string = undefined
    fkiUserIDOwner?:number = undefined
    objAudit?:CommonAudit = undefined
    objAttachmentProof?:AttachmentResponseCompound = undefined
    objAttachmentProofdocument?:AttachmentResponseCompound = undefined
    a_objAttachmentAttachment?:Array<AttachmentResponseCompound> = undefined
    a_objAttachmentVersion?:Array<AttachmentResponseCompound> = undefined
}

/**
 * @export 
 * A CustomAttachmentResponse Validation Object
 * @class ValidationObjectCustomAttachmentResponse
 */
export class ValidationObjectCustomAttachmentResponse {
   pkiAttachmentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiComputerID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: false
   }
   fkiAdjustmentID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiAgentID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiBankaccountID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   fkiBrokerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiCommissionadvanceID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiCommunicationID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiCustomerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiCustomertemplateID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiDepositID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiDeposittransitchequeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiElectronicfundstransferID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: false
   }
   fkiEmployeeID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiExternalbrokerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzcomadvanceserverID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiEzcomcompanyID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiGhacqcontractID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiInscriptionID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiInscriptiontempID = {
      type: 'integer',
      minimum: 1,
      maximum: 16777215,
      required: false
   }
   fkiInscriptionnotauthenticatedID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiInvoiceID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiBuyercontractID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: false
   }
   fkiFranchisebrokerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiFranchiseagenceID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiFranchiseofficeID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiFranchisefranchiseID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiFranchisecomplaintID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiLeadID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiMarketingprogramID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   fkiMarketingfollowID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiNotaryID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiOfficetaxreportID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiOtherincomeID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: false
   }
   fkiPaymentpreparationID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiPurchaseID = {
      type: 'integer',
      required: false
   }
   fkiSalaryID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiSupplierID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiTranqcontractID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiTemplateID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiInscriptionchecklistID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiFolderID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiRejectedoffertopurchaseID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: false
   }
   fkiDisclosureID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiReconciliationID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiEzsigndocumentIDReference = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   eAttachmentDocumenttype = {
      type: 'enum',
      allowableValues: ['Adjustment','Agent','Bankaccount','Broker','Buyercontract','Commissionadvance','Communication','Customer','Customertemplate','Deposit','Deposittransitcheque','Disclosure','Electronicfundstransfer','Employee','Externalbroker','Ezcomadvanceserver','Ezcomcompany','Ezsigndocument','EzsigndocumentProof','EzsigndocumentProofdocument','Ezsigndocumentgroup','EzsigndocumentgroupProof','EzsigndocumentgroupProofdocument','EzsigndocumentAttachment','Folder','Franchiseagence','Franchisebroker','Franchisecomplaint','Franchisefranchise','Franchiseoffice','Ghacqcontract','Inscription','Inscriptionnotauthenticated','Inscriptiontemp','Invoice','Lead','Marketingfollow','Marketingprogram','Notary','Officetaxreport','Otherincome','Paymentpreparation','Purchase','Reconciliation','Rejectedoffertopurchase','Salary','Supplier','Template','Tranqcontract'],
      required: true
   }
   sAttachmentName = {
      type: 'string',
      pattern: /^.{0,75}$/,
      required: true
   }
   eAttachmentPrivacy = {
      type: 'enum',
      allowableValues: ['All','Inscriptor','Seller','Administration','Creator','Specificuser'],
      required: true
   }
   fkiUserIDSpecific = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   eAttachmentType = {
      type: 'enum',
      allowableValues: ['Other','Pdf','PdfGenerated','PdfScanned','Ezsign'],
      required: true
   }
   iAttachmentSize = {
      type: 'integer',
      minimum: 0,
      maximum: 4294967295,
      required: true
   }
   iAttachmentEDMmoduleflag = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   sAttachmentMD5 = {
      type: 'string',
      pattern: /^.{0,32}$/,
      required: true
   }
   bAttachmentDeleted = {
      type: 'boolean',
      required: true
   }
   bAttachmentValid = {
      type: 'boolean',
      required: true
   }
   eAttachmentVerified = {
      type: 'enum',
      allowableValues: ['No','Yes','Rejected'],
      required: true
   }
   tAttachmentRejectioncomment = {
      type: 'string',
      pattern: /^.{0,65535}$/,
      required: false
   }
   fkiUserIDOwner = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   objAudit = new ValidationObjectCommonAudit()
   objAttachmentProof = new ValidationObjectAttachmentResponseCompound()
   objAttachmentProofdocument = new ValidationObjectAttachmentResponseCompound()
   a_objAttachmentAttachment = {
      type: 'array',
      required: false
   }
   a_objAttachmentVersion = {
      type: 'array',
      required: false
   }
} 


