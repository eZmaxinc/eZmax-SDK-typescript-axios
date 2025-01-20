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
import type { AddressResponse } from './address-response';
// May contain unused imports in some cases
// @ts-ignore
import type { ContactinformationsResponse } from './contactinformations-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EmailResponse } from './email-response';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEContactinformationsType } from './field-econtactinformations-type';
// May contain unused imports in some cases
// @ts-ignore
import type { PhoneResponseCompound } from './phone-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { WebsiteResponse } from './website-response';

/**
 * @type ContactinformationsResponseCompound
 * A Contactinformations Object
 * @export
 */
/*export type ContactinformationsResponseCompound = ContactinformationsResponse;*/
export interface ContactinformationsResponseCompound {
    /**
     * The unique ID of the Contactinformations
     * @type {number}
     * @memberof ContactinformationsResponseCompound
     */
    pkiContactinformationsID:number 
    /**
     * The unique ID of the Address
     * @type {number}
     * @memberof ContactinformationsResponseCompound
     */
    fkiAddressIDDefault?:number 
    /**
     * The unique ID of the Phone.
     * @type {number}
     * @memberof ContactinformationsResponseCompound
     */
    fkiPhoneIDDefault?:number 
    /**
     * The unique ID of the Email
     * @type {number}
     * @memberof ContactinformationsResponseCompound
     */
    fkiEmailIDDefault?:number 
    /**
     * The unique ID of the Website Default
     * @type {number}
     * @memberof ContactinformationsResponseCompound
     */
    fkiWebsiteIDDefault?:number 
    /**
     * 
     * @type {FieldEContactinformationsType}
     * @memberof ContactinformationsResponseCompound
     */
    eContactinformationsType:FieldEContactinformationsType 
    /**
     * The url of the Contactinformations
     * @type {string}
     * @memberof ContactinformationsResponseCompound
     */
    sContactinformationsUrl?:string 
    /**
     * An Address Object and children to create a complete structure
     * @type {AddressResponse}
     * @memberof ContactinformationsResponseCompound
     */
    objAddressDefault?:AddressResponse 
    /**
     * 
     * @type {PhoneResponseCompound}
     * @memberof ContactinformationsResponseCompound
     */
    objPhoneDefault?:PhoneResponseCompound 
    /**
     * An Email Object and children to create a complete structure
     * @type {EmailResponse}
     * @memberof ContactinformationsResponseCompound
     */
    objEmailDefault?:EmailResponse 
    /**
     * A Website Object and children to create a complete structure
     * @type {WebsiteResponse}
     * @memberof ContactinformationsResponseCompound
     */
    objWebsiteDefault?:WebsiteResponse 
    /**
     * 
     * @type {Array<AddressResponseCompound>}
     * @memberof ContactinformationsResponseCompound
     */
    a_objAddress:Array<AddressResponseCompound> 
    /**
     * 
     * @type {Array<PhoneResponseCompound>}
     * @memberof ContactinformationsResponseCompound
     */
    a_objPhone:Array<PhoneResponseCompound> 
    /**
     * 
     * @type {Array<EmailResponseCompound>}
     * @memberof ContactinformationsResponseCompound
     */
    a_objEmail:Array<EmailResponseCompound> 
    /**
     * 
     * @type {Array<WebsiteResponseCompound>}
     * @memberof ContactinformationsResponseCompound
     */
    a_objWebsite:Array<WebsiteResponseCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectAddressResponse } from './'
// @ts-ignore
import { DataObjectPhoneResponseCompound } from './'
// @ts-ignore
import { DataObjectEmailResponse } from './'
// @ts-ignore
import { DataObjectWebsiteResponse } from './'
// @ts-ignore
import { ValidationObjectAddressResponse } from './'
// @ts-ignore
import { ValidationObjectPhoneResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEmailResponse } from './'
// @ts-ignore
import { ValidationObjectWebsiteResponse } from './'

/**
 * @export 
 * A ContactinformationsResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectContactinformationsResponseCompound
 */
export class DataObjectContactinformationsResponseCompound {
    pkiContactinformationsID:number = 0
    fkiAddressIDDefault?:number = undefined
    fkiPhoneIDDefault?:number = undefined
    fkiEmailIDDefault?:number = undefined
    fkiWebsiteIDDefault?:number = undefined
    eContactinformationsType:FieldEContactinformationsType = 'BankAccount'
    sContactinformationsUrl?:string = undefined
    objAddressDefault?:AddressResponse = undefined
    objPhoneDefault?:PhoneResponseCompound = undefined
    objEmailDefault?:EmailResponse = undefined
    objWebsiteDefault?:WebsiteResponse = undefined
    a_objAddress:Array<AddressResponseCompound> = []
    a_objPhone:Array<PhoneResponseCompound> = []
    a_objEmail:Array<EmailResponseCompound> = []
    a_objWebsite:Array<WebsiteResponseCompound> = []
}

/**
 * @export 
 * A ContactinformationsResponseCompound Validation Object
 * @class ValidationObjectContactinformationsResponseCompound
 */
export class ValidationObjectContactinformationsResponseCompound {
   pkiContactinformationsID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiAddressIDDefault = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiPhoneIDDefault = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEmailIDDefault = {
      type: 'integer',
      minimum: 1,
      maximum: 16777215,
      required: false
   }
   fkiWebsiteIDDefault = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   eContactinformationsType = {
      type: 'enum',
      allowableValues: ['BankAccount','ContactObject','CreditCard','Customer','ExternalBroker','ExternalBrokerFirm','EzcomCompany','FinancialInstitution','FranchiseCompany','FranchiseOffice','Supplier'],
      required: true
   }
   sContactinformationsUrl = {
      type: 'string',
      pattern: /^.{0,255}$/,
      required: false
   }
   objAddressDefault = new ValidationObjectAddressResponse()
   objPhoneDefault = new ValidationObjectPhoneResponseCompound()
   objEmailDefault = new ValidationObjectEmailResponse()
   objWebsiteDefault = new ValidationObjectWebsiteResponse()
   a_objAddress = {
      type: 'array',
      required: true
   }
   a_objPhone = {
      type: 'array',
      required: true
   }
   a_objEmail = {
      type: 'array',
      required: true
   }
   a_objWebsite = {
      type: 'array',
      required: true
   }
} 


