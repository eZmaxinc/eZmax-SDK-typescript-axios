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
import { CreditcardclientRequest } from './creditcardclient-request';
// May contain unused imports in some cases
// @ts-ignore
import { CreditcarddetailRequest } from './creditcarddetail-request';

/**
 * @type CreditcardclientRequestCompound
 * A Creditcardclient Object and children
 * @export
 */
/*export type CreditcardclientRequestCompound = CreditcardclientRequest;*/
export interface CreditcardclientRequestCompound {
    /**
     * The unique ID of the Creditcardclient
     * @type {number}
     * @memberof CreditcardclientRequestCompound
     */
    pkiCreditcardclientID?:number 
    /**
     * The creditcard token identifier
     * @type {string}
     * @memberof CreditcardclientRequestCompound
     */
    fksCreditcardtokenID?:string 
    /**
     * Whether if it\'s an relationisdefault
     * @type {boolean}
     * @memberof CreditcardclientRequestCompound
     */
    bCreditcardclientrelationIsdefault:boolean 
    /**
     * The description of the Creditcardclient
     * @type {string}
     * @memberof CreditcardclientRequestCompound
     */
    sCreditcardclientDescription:string 
    /**
     * Whether the creditcardclient is active or not
     * @type {boolean}
     * @memberof CreditcardclientRequestCompound
     */
    bCreditcardclientIsactive:boolean 
    /**
     * Whether if it\'s an allowedagencypayment
     * @type {boolean}
     * @memberof CreditcardclientRequestCompound
     */
    bCreditcardclientAllowedagencypayment:boolean 
    /**
     * Whether if it\'s an allowedroyallepageprotection
     * @type {boolean}
     * @memberof CreditcardclientRequestCompound
     */
    bCreditcardclientAllowedroyallepageprotection:boolean 
    /**
     * Whether if it\'s an allowedtranquillit
     * @type {boolean}
     * @memberof CreditcardclientRequestCompound
     */
    bCreditcardclientAllowedtranquillit:boolean 
    /**
     * 
     * @type {CreditcarddetailRequest}
     * @memberof CreditcardclientRequestCompound
     */
    objCreditcarddetail:CreditcarddetailRequest 
    /**
     * The creditcard card CVV
     * @type {string}
     * @memberof CreditcardclientRequestCompound
     */
    sCreditcardclientCVV:string 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCreditcarddetailRequest } from './'
// @ts-ignore
import { ValidationObjectCreditcarddetailRequest } from './'

/**
 * @export 
 * A CreditcardclientRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardclientRequestCompound
 */
export class DataObjectCreditcardclientRequestCompound {
    pkiCreditcardclientID?:number = undefined
    fksCreditcardtokenID?:string = undefined
    bCreditcardclientrelationIsdefault:boolean = false
    sCreditcardclientDescription:string = ''
    bCreditcardclientIsactive:boolean = false
    bCreditcardclientAllowedagencypayment:boolean = false
    bCreditcardclientAllowedroyallepageprotection:boolean = false
    bCreditcardclientAllowedtranquillit:boolean = false
    objCreditcarddetail:CreditcarddetailRequest = new DataObjectCreditcarddetailRequest()
    sCreditcardclientCVV:string = ''
}

/**
 * @export 
 * A CreditcardclientRequestCompound Validation Object
 * @class ValidationObjectCreditcardclientRequestCompound
 */
export class ValidationObjectCreditcardclientRequestCompound {
   pkiCreditcardclientID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fksCreditcardtokenID = {
      type: 'string',
      pattern: '/^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$/',
      required: false
   }
   bCreditcardclientrelationIsdefault = {
      type: 'boolean',
      required: true
   }
   sCreditcardclientDescription = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: true
   }
   bCreditcardclientIsactive = {
      type: 'boolean',
      required: true
   }
   bCreditcardclientAllowedagencypayment = {
      type: 'boolean',
      required: true
   }
   bCreditcardclientAllowedroyallepageprotection = {
      type: 'boolean',
      required: true
   }
   bCreditcardclientAllowedtranquillit = {
      type: 'boolean',
      required: true
   }
   objCreditcarddetail = new ValidationObjectCreditcarddetailRequest()
   sCreditcardclientCVV = {
      type: 'string',
      pattern: '/^[0-9]{3,4}$/',
      required: true
   }
} 


