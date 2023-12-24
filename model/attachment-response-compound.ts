/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
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
 * @type AttachmentResponseCompound
 * A Attachment Object
 * @export
 */
/** export type AttachmentResponseCompound = AttachmentResponse; */
export interface AttachmentResponseCompound {
    /**
     * The unique ID of the Attachment.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    pkiAttachmentID:number 
    /**
     * The unique ID of the Computer
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiComputerID?:number 
    /**
     * The unique ID of the Adjustment
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiAdjustmentID?:number 
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiAgentID?:number 
    /**
     * The unique ID of the Bankaccount
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiBankaccountID?:number 
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiBrokerID?:number 
    /**
     * The unique ID of the Commissionadvance
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiCommissionadvanceID?:number 
    /**
     * The unique ID of the Communication.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiCommunicationID?:number 
    /**
     * The unique ID of the Customer.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiCustomerID?:number 
    /**
     * The unique ID of the Customertemplate
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiCustomertemplateID?:number 
    /**
     * The unique ID of the Deposit
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiDepositID?:number 
    /**
     * The unique ID of the Deposittransitcheque
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiDeposittransitchequeID?:number 
    /**
     * The unique ID of the Electronicfundstransfer
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiElectronicfundstransferID?:number 
    /**
     * The unique ID of the Employee.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiEmployeeID?:number 
    /**
     * The unique ID of the Externalbroker.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiExternalbrokerID?:number 
    /**
     * The unique ID of the Ezcomadvanceserver
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiEzcomadvanceserverID?:number 
    /**
     * The unique ID of the Ezcomcompany
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiEzcomcompanyID?:number 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiEzsigndocumentID?:number 
    /**
     * The unique ID of the Ghacqcontract
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiGhacqcontractID?:number 
    /**
     * The unique ID of the Inscription.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiInscriptionID?:number 
    /**
     * The unique ID of the Inscriptiontemp
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiInscriptiontempID?:number 
    /**
     * The unique ID of the Inscriptionnotauthenticated.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiInscriptionnotauthenticatedID?:number 
    /**
     * The unique ID of the Invoice.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiInvoiceID?:number 
    /**
     * The unique ID of the Buyercontract
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiBuyercontractID?:number 
    /**
     * The unique ID of the Franchisebroker
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiFranchisebrokerID?:number 
    /**
     * The unique ID of the Franchiseagence
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiFranchiseagenceID?:number 
    /**
     * The unique ID of the Franchisereoffice
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiFranchiseofficeID?:number 
    /**
     * The unique ID of the Franchisefranchise
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiFranchisefranchiseID?:number 
    /**
     * The unique ID of the Franchisecomplaint
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiFranchisecomplaintID?:number 
    /**
     * The unique ID of the Lead
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiLeadID?:number 
    /**
     * The unique ID of the Marketingprogram
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiMarketingprogramID?:number 
    /**
     * The unique ID of the Marketingfollow
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiMarketingfollowID?:number 
    /**
     * The unique ID of the Notary.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiNotaryID?:number 
    /**
     * The unique ID of the Officetaxreport
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiOfficetaxreportID?:number 
    /**
     * The unique ID of the Otherincome
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiOtherincomeID?:number 
    /**
     * The unique ID of the Paymentpreparation
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiPaymentpreparationID?:number 
    /**
     * The unique ID of the Purchase
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiPurchaseID?:number 
    /**
     * The unique ID of the Salary
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiSalaryID?:number 
    /**
     * The unique ID of the Supplier.
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiSupplierID?:number 
    /**
     * The unique ID of the Tranqcontract
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiTranqcontractID?:number 
    /**
     * The unique ID of the Template
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiTemplateID?:number 
    /**
     * The unique ID of the Inscriptionchecklist
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiInscriptionchecklistID?:number 
    /**
     * The unique ID of the Folder
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiFolderID?:number 
    /**
     * The unique ID of the Rejectedoffertopurchase
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiRejectedoffertopurchaseID?:number 
    /**
     * The unique ID of the Disclosure
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiDisclosureID?:number 
    /**
     * The unique ID of the Reconciliation
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiReconciliationID?:number 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiEzsigndocumentIDReference?:number 
    /**
     * 
     * @type {FieldEAttachmentDocumenttype}
     * @memberof AttachmentResponseCompound
     */
    eAttachmentDocumenttype:FieldEAttachmentDocumenttype 
    /**
     * The name of the Attachment
     * @type {string}
     * @memberof AttachmentResponseCompound
     */
    sAttachmentName:string 
    /**
     * 
     * @type {FieldEAttachmentPrivacy}
     * @memberof AttachmentResponseCompound
     */
    eAttachmentPrivacy:FieldEAttachmentPrivacy 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiUserIDSpecific?:number 
    /**
     * 
     * @type {FieldEAttachmentType}
     * @memberof AttachmentResponseCompound
     */
    eAttachmentType:FieldEAttachmentType 
    /**
     * The size of the Attachment
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    iAttachmentSize:number 
    /**
     * The edmmoduleflag of the Attachment
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    iAttachmentEDMmoduleflag?:number 
    /**
     * The md5 of the Attachment
     * @type {string}
     * @memberof AttachmentResponseCompound
     */
    sAttachmentMD5:string 
    /**
     * Whether if it\'s deleted
     * @type {boolean}
     * @memberof AttachmentResponseCompound
     */
    bAttachmentDeleted:boolean 
    /**
     * Whether if it\'s valid
     * @type {boolean}
     * @memberof AttachmentResponseCompound
     */
    bAttachmentValid:boolean 
    /**
     * 
     * @type {FieldEAttachmentVerified}
     * @memberof AttachmentResponseCompound
     */
    eAttachmentVerified:FieldEAttachmentVerified 
    /**
     * The rejectioncomment of the Attachment
     * @type {string}
     * @memberof AttachmentResponseCompound
     */
    tAttachmentRejectioncomment?:string 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof AttachmentResponseCompound
     */
    fkiUserIDOwner?:number 
    /**
     * 
     * @type {CommonAudit}
     * @memberof AttachmentResponseCompound
     */
    objAudit?:CommonAudit 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A AttachmentResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectAttachmentResponseCompound
 */
export class DataObjectAttachmentResponseCompound {
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
}

/**
 * @export 
 * A AttachmentResponseCompound Validation Object
 * @class ValidationObjectAttachmentResponseCompound
 */
export class ValidationObjectAttachmentResponseCompound {
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
      pattern: '/^.{0,75}$/',
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
      pattern: '/^.{0,32}$/',
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
      pattern: '/^.{0,65535}$/',
      required: false
   }
   fkiUserIDOwner = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   objAudit = new ValidationObjectCommonAudit()
} 


