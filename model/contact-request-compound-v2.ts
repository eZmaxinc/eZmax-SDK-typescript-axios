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
import type { ContactRequestV2 } from './contact-request-v2';
// May contain unused imports in some cases
// @ts-ignore
import type { ContactinformationsRequestCompoundV2 } from './contactinformations-request-compound-v2';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEContactType } from './field-econtact-type';

/**
 * @type ContactRequestCompoundV2
 * A Contact Object and children to create a complete structure
 * @export
 */
/*export type ContactRequestCompoundV2 = ContactRequestV2;*/
export interface ContactRequestCompoundV2 {
    /**
     * The unique ID of the Contacttitle.  Valid values:  |Value|Description| |-|-| |1|Ms.| |2|Mr.| |4|(Blank)| |5|Me (For Notaries)|
     * @type {number}
     * @memberof ContactRequestCompoundV2
     */
    fkiContacttitleID:number 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof ContactRequestCompoundV2
     */
    fkiLanguageID:number 
    /**
     * 
     * @type {FieldEContactType}
     * @memberof ContactRequestCompoundV2
     */
    eContactType:FieldEContactType 
    /**
     * The First name of the contact
     * @type {string}
     * @memberof ContactRequestCompoundV2
     */
    sContactFirstname:string 
    /**
     * The Last name of the contact
     * @type {string}
     * @memberof ContactRequestCompoundV2
     */
    sContactLastname:string 
    /**
     * The Company name of the contact
     * @type {string}
     * @memberof ContactRequestCompoundV2
     */
    sContactCompany?:string 
    /**
     * The Birth Date of the contact
     * @type {string}
     * @memberof ContactRequestCompoundV2
     */
    dtContactBirthdate?:string 
    /**
     * The occupation of the Contact
     * @type {string}
     * @memberof ContactRequestCompoundV2
     */
    sContactOccupation?:string 
    /**
     * The note of the Contact
     * @type {string}
     * @memberof ContactRequestCompoundV2
     */
    tContactNote?:string 
    /**
     * Whether the contact is active or not
     * @type {boolean}
     * @memberof ContactRequestCompoundV2
     */
    bContactIsactive?:boolean 
    /**
     * 
     * @type {ContactinformationsRequestCompoundV2}
     * @memberof ContactRequestCompoundV2
     */
    objContactinformations:ContactinformationsRequestCompoundV2 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectContactinformationsRequestCompoundV2 } from './'
// @ts-ignore
import { ValidationObjectContactinformationsRequestCompoundV2 } from './'

/**
 * @export 
 * A ContactRequestCompoundV2 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectContactRequestCompoundV2
 */
export class DataObjectContactRequestCompoundV2 {
    fkiContacttitleID:number = 0
    fkiLanguageID:number = 0
    eContactType:FieldEContactType = 'Agent'
    sContactFirstname:string = ''
    sContactLastname:string = ''
    sContactCompany?:string = undefined
    dtContactBirthdate?:string = undefined
    sContactOccupation?:string = undefined
    tContactNote?:string = undefined
    bContactIsactive?:boolean = undefined
    objContactinformations:ContactinformationsRequestCompoundV2 = new DataObjectContactinformationsRequestCompoundV2()
}

/**
 * @export 
 * A ContactRequestCompoundV2 Validation Object
 * @class ValidationObjectContactRequestCompoundV2
 */
export class ValidationObjectContactRequestCompoundV2 {
   fkiContacttitleID = {
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
   eContactType = {
      type: 'enum',
      allowableValues: ['Agent','Assistant','BankAccount','Borrower','Buyer','Company','ContractCreator','Creditcardmerchant','Customer','Depositreceipt','Employee','ExternalBroker','EzsignSigner','EzsignUser','EzcomAgent','EzcomApprover','FinancialInstitution','FranchiseBroker','Franchisefranchisecontact','Franchisefranchisesignatory','FranchiseOfficeBroker','FranchiseCompany','FranchiseOwner','Lead','MarketingCampaignSample','Notary','Payer','Petowner','PrivateTo','RewardMember','RewardRepresentative','Seller','Shared','Supplier','Survey','Inspector'],
      required: true
   }
   sContactFirstname = {
      type: 'string',
      required: true
   }
   sContactLastname = {
      type: 'string',
      required: true
   }
   sContactCompany = {
      type: 'string',
      required: false
   }
   dtContactBirthdate = {
      type: 'string',
      required: false
   }
   sContactOccupation = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
   tContactNote = {
      type: 'string',
      pattern: /^.{0,32000}$/,
      required: false
   }
   bContactIsactive = {
      type: 'boolean',
      required: false
   }
   objContactinformations = new ValidationObjectContactinformationsRequestCompoundV2()
} 


