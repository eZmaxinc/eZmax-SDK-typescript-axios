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
import { CustomerRequest } from './customer-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECustomerMarketingcorrespondence } from './field-ecustomer-marketingcorrespondence';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECustomerType } from './field-ecustomer-type';

/**
 * @type CustomerRequestCompound
 * A Customer Object and children
 * @export
 */
/*export type CustomerRequestCompound = CustomerRequest;*/
export interface CustomerRequestCompound {
    /**
     * The unique ID of the Customer.
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    pkiCustomerID?:number 
    /**
     * The unique ID of the Company
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiCompanyID:number 
    /**
     * The unique ID of the Customergroup
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiCustomergroupID:number 
    /**
     * The name of the Customer
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    sCustomerName:string 
    /**
     * The unique ID of the Contactinformations
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiContactinformationsID:number 
    /**
     * The unique ID of the Contactcontainer
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiContactcontainerID:number 
    /**
     * The unique ID of the Image
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiImageID:number 
    /**
     * The unique ID of the Glaccountcontainer
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiGlaccountcontainerID:number 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiLanguageID:number 
    /**
     * The unique ID of the Department
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiDepartmentID:number 
    /**
     * The unique ID of the Paymentmethod
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiPaymentmethodID:number 
    /**
     * The unique ID of the Electronicfundstransferbankaccount
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiElectronicfundstransferbankaccountID:number 
    /**
     * The unique ID of the Electronicfundstransferbankaccount
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiElectronicfundstransferbankaccountIDDirectdebit:number 
    /**
     * The unique ID of the Sendingmethod
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiSendingmethodID:number 
    /**
     * The unique ID of the Taxassignment.  Valid values:  |Value|Description| |-|-| |1|No tax| |2|GST| |3|HST (ON)| |4|HST (NB)| |5|HST (NS)| |6|HST (NL)| |7|HST (PE)| |8|GST + QST (QC)| |9|GST + QST (QC) Non-Recoverable| |10|GST + PST (BC)| |11|GST + PST (SK)| |12|GST + RST (MB)| |13|GST + PST (BC) Non-Recoverable| |14|GST + PST (SK) Non-Recoverable| |15|GST + RST (MB) Non-Recoverable|
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiTaxassignmentID:number 
    /**
     * The unique ID of the Attendancestatus
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiAttendancestatusID:number 
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiAgentIDVariableexpensechargeto:number 
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiBrokerIDVariableexpensechargeto:number 
    /**
     * The unique ID of the Customer.
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiCustomerIDVariableexpensechargeto:number 
    /**
     * The unique ID of the Glaccountcontainer
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiGlaccountcontainerIDVariableexpensechargeto:number 
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiAgentIDSupplychargechargeto:number 
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiBrokerIDSupplychargechargeto:number 
    /**
     * The unique ID of the Customer.
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiCustomerIDSupplychargechargeto:number 
    /**
     * The unique ID of the Glaccountcontainer
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiGlaccountcontainerIDSupplychargechargeto:number 
    /**
     * The unique ID of the Invoicealternatelogo
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiInvoicealternatelogoID:number 
    /**
     * The unique ID of the Synchronizationlinkserver
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    fkiSynchronizationlinkserverID:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    efkiUserID?:number 
    /**
     * The code of the Customer
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    efksCustomerCode?:string 
    /**
     * The code of the Customer
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    sCustomerCode:string 
    /**
     * The fulltimeequivalent of the Customer
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    dCustomerFulltimeequivalent:string 
    /**
     * The photocopiercode of the Customer
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    iCustomerPhotocopiercode:number 
    /**
     * The longdistancecode of the Customer
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    iCustomerLongdistancecode:number 
    /**
     * The timewindowstart of the Customer
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    iCustomerTimewindowstart:number 
    /**
     * The timewindowend of the Customer
     * @type {number}
     * @memberof CustomerRequestCompound
     */
    iCustomerTimewindowend:number 
    /**
     * The minimumchargeableinterests of the Customer
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    dCustomerMinimumchargeableinterests:string 
    /**
     * The birthdate of the Customer
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    dtCustomerBirthdate:string 
    /**
     * The transfer of the Customer
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    dtCustomerTransfer:string 
    /**
     * The transferappointment of the Customer
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    dtCustomerTransferappointment:string 
    /**
     * The transfersurvey of the Customer
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    dtCustomerTransfersurvey:string 
    /**
     * Whether the customer is active or not
     * @type {boolean}
     * @memberof CustomerRequestCompound
     */
    bCustomerIsactive:boolean 
    /**
     * Whether if it\'s an variableexpensefinanced
     * @type {boolean}
     * @memberof CustomerRequestCompound
     */
    bCustomerVariableexpensefinanced:boolean 
    /**
     * Whether if it\'s an variableexpensefinancedtaxes
     * @type {boolean}
     * @memberof CustomerRequestCompound
     */
    bCustomerVariableexpensefinancedtaxes:boolean 
    /**
     * Whether if it\'s an supplychargefinanced
     * @type {boolean}
     * @memberof CustomerRequestCompound
     */
    bCustomerSupplychargefinanced:boolean 
    /**
     * Whether if it\'s an supplychargefinancedtaxes
     * @type {boolean}
     * @memberof CustomerRequestCompound
     */
    bCustomerSupplychargefinancedtaxes:boolean 
    /**
     * Whether if it\'s an attendance
     * @type {boolean}
     * @memberof CustomerRequestCompound
     */
    bCustomerAttendance:boolean 
    /**
     * 
     * @type {FieldECustomerType}
     * @memberof CustomerRequestCompound
     */
    eCustomerType:FieldECustomerType 
    /**
     * 
     * @type {FieldECustomerMarketingcorrespondence}
     * @memberof CustomerRequestCompound
     */
    eCustomerMarketingcorrespondence:FieldECustomerMarketingcorrespondence 
    /**
     * Whether if it\'s an blackcopycarbon
     * @type {boolean}
     * @memberof CustomerRequestCompound
     */
    bCustomerBlackcopycarbon:boolean 
    /**
     * Whether if it\'s an unsubscribeinfo
     * @type {boolean}
     * @memberof CustomerRequestCompound
     */
    bCustomerUnsubscribeinfo:boolean 
    /**
     * The comment of the Customer
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    tCustomerComment:string 
    /**
     * 
     * @type {string}
     * @memberof CustomerRequestCompound
     */
    IMPORTID?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomerRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomerRequestCompound
 */
export class DataObjectCustomerRequestCompound {
    pkiCustomerID?:number = undefined
    fkiCompanyID:number = 0
    fkiCustomergroupID:number = 0
    sCustomerName:string = ''
    fkiContactinformationsID:number = 0
    fkiContactcontainerID:number = 0
    fkiImageID:number = 0
    fkiGlaccountcontainerID:number = 0
    fkiLanguageID:number = 0
    fkiDepartmentID:number = 0
    fkiPaymentmethodID:number = 0
    fkiElectronicfundstransferbankaccountID:number = 0
    fkiElectronicfundstransferbankaccountIDDirectdebit:number = 0
    fkiSendingmethodID:number = 0
    fkiTaxassignmentID:number = 0
    fkiAttendancestatusID:number = 0
    fkiAgentIDVariableexpensechargeto:number = 0
    fkiBrokerIDVariableexpensechargeto:number = 0
    fkiCustomerIDVariableexpensechargeto:number = 0
    fkiGlaccountcontainerIDVariableexpensechargeto:number = 0
    fkiAgentIDSupplychargechargeto:number = 0
    fkiBrokerIDSupplychargechargeto:number = 0
    fkiCustomerIDSupplychargechargeto:number = 0
    fkiGlaccountcontainerIDSupplychargechargeto:number = 0
    fkiInvoicealternatelogoID:number = 0
    fkiSynchronizationlinkserverID:number = 0
    efkiUserID?:number = undefined
    efksCustomerCode?:string = undefined
    sCustomerCode:string = ''
    dCustomerFulltimeequivalent:string = ''
    iCustomerPhotocopiercode:number = 0
    iCustomerLongdistancecode:number = 0
    iCustomerTimewindowstart:number = 0
    iCustomerTimewindowend:number = 0
    dCustomerMinimumchargeableinterests:string = ''
    dtCustomerBirthdate:string = ''
    dtCustomerTransfer:string = ''
    dtCustomerTransferappointment:string = ''
    dtCustomerTransfersurvey:string = ''
    bCustomerIsactive:boolean = false
    bCustomerVariableexpensefinanced:boolean = false
    bCustomerVariableexpensefinancedtaxes:boolean = false
    bCustomerSupplychargefinanced:boolean = false
    bCustomerSupplychargefinancedtaxes:boolean = false
    bCustomerAttendance:boolean = false
    eCustomerType:FieldECustomerType = 'Normal'
    eCustomerMarketingcorrespondence:FieldECustomerMarketingcorrespondence = 'No'
    bCustomerBlackcopycarbon:boolean = false
    bCustomerUnsubscribeinfo:boolean = false
    tCustomerComment:string = ''
    IMPORTID?:string = undefined
}

/**
 * @export 
 * A CustomerRequestCompound Validation Object
 * @class ValidationObjectCustomerRequestCompound
 */
export class ValidationObjectCustomerRequestCompound {
   pkiCustomerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiCompanyID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   fkiCustomergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sCustomerName = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: true
   }
   fkiContactinformationsID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiContactcontainerID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiImageID = {
      type: 'integer',
      required: true
   }
   fkiGlaccountcontainerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   fkiDepartmentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiPaymentmethodID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   fkiElectronicfundstransferbankaccountID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiElectronicfundstransferbankaccountIDDirectdebit = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiSendingmethodID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   fkiTaxassignmentID = {
      type: 'integer',
      minimum: 0,
      maximum: 15,
      required: true
   }
   fkiAttendancestatusID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiAgentIDVariableexpensechargeto = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiBrokerIDVariableexpensechargeto = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiCustomerIDVariableexpensechargeto = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiGlaccountcontainerIDVariableexpensechargeto = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiAgentIDSupplychargechargeto = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiBrokerIDSupplychargechargeto = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiCustomerIDSupplychargechargeto = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiGlaccountcontainerIDSupplychargechargeto = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiInvoicealternatelogoID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   fkiSynchronizationlinkserverID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   efkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   efksCustomerCode = {
      type: 'string',
      pattern: /^.{0,6}$/,
      required: false
   }
   sCustomerCode = {
      type: 'string',
      pattern: /^.{0,6}$/,
      required: true
   }
   dCustomerFulltimeequivalent = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,3}?\.[\d]{2}$/,
      required: true
   }
   iCustomerPhotocopiercode = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iCustomerLongdistancecode = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iCustomerTimewindowstart = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   iCustomerTimewindowend = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   dCustomerMinimumchargeableinterests = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: true
   }
   dtCustomerBirthdate = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/,
      required: true
   }
   dtCustomerTransfer = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
   dtCustomerTransferappointment = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
   dtCustomerTransfersurvey = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
   bCustomerIsactive = {
      type: 'boolean',
      required: true
   }
   bCustomerVariableexpensefinanced = {
      type: 'boolean',
      required: true
   }
   bCustomerVariableexpensefinancedtaxes = {
      type: 'boolean',
      required: true
   }
   bCustomerSupplychargefinanced = {
      type: 'boolean',
      required: true
   }
   bCustomerSupplychargefinancedtaxes = {
      type: 'boolean',
      required: true
   }
   bCustomerAttendance = {
      type: 'boolean',
      required: true
   }
   eCustomerType = {
      type: 'enum',
      allowableValues: ['Normal','Vetrx-Server','Reward-Administration','Reward-Representative','Reward-Server'],
      required: true
   }
   eCustomerMarketingcorrespondence = {
      type: 'enum',
      allowableValues: ['No','Email','Mail','Any'],
      required: true
   }
   bCustomerBlackcopycarbon = {
      type: 'boolean',
      required: true
   }
   bCustomerUnsubscribeinfo = {
      type: 'boolean',
      required: true
   }
   tCustomerComment = {
      type: 'string',
      pattern: /^.{0,16777215}$/,
      required: true
   }
   IMPORTID = {
      type: 'string',
      pattern: /^.{0,15}$/,
      required: false
   }
} 


