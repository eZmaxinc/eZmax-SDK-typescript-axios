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
import { CreditcarddetailRequest } from './creditcarddetail-request';

/**
 * A Creditcardclient Object
 * @export
 * @interface CreditcardclientRequest
 */
export interface CreditcardclientRequest {
    /**
     * The unique ID of the Creditcardclient
     * @type {number}
     * @memberof CreditcardclientRequest
     */
    /*'pkiCreditcardclientID'?: number;*/
    'pkiCreditcardclientID'?: number;
    /**
     * The creditcard token identifier
     * @type {string}
     * @memberof CreditcardclientRequest
     */
    /*'fksCreditcardtokenID'?: string;*/
    'fksCreditcardtokenID'?: string;
    /**
     * Whether if it\'s the creditcardclient is the default one
     * @type {boolean}
     * @memberof CreditcardclientRequest
     */
    /*'bCreditcardclientrelationIsdefault': boolean;*/
    'bCreditcardclientrelationIsdefault': boolean;
    /**
     * The description of the Creditcardclient
     * @type {string}
     * @memberof CreditcardclientRequest
     */
    /*'sCreditcardclientDescription': string;*/
    'sCreditcardclientDescription': string;
    /**
     * Whether if it\'s an allowedagencypayment
     * @type {boolean}
     * @memberof CreditcardclientRequest
     */
    /*'bCreditcardclientAllowedcompanypayment': boolean;*/
    'bCreditcardclientAllowedcompanypayment': boolean;
    /**
     * Whether if it\'s an allowedroyallepageprotection
     * @type {boolean}
     * @memberof CreditcardclientRequest
     */
    /*'bCreditcardclientAllowedezsign': boolean;*/
    'bCreditcardclientAllowedezsign': boolean;
    /**
     * Whether if it\'s an allowedtranquillit
     * @type {boolean}
     * @memberof CreditcardclientRequest
     */
    /*'bCreditcardclientAllowedtranquillit': boolean;*/
    'bCreditcardclientAllowedtranquillit': boolean;
    /**
     * 
     * @type {CreditcarddetailRequest}
     * @memberof CreditcardclientRequest
     */
    /*'objCreditcarddetail': CreditcarddetailRequest;*/
    'objCreditcarddetail': CreditcarddetailRequest;
    /**
     * The creditcard card CVV
     * @type {string}
     * @memberof CreditcardclientRequest
     */
    /*'sCreditcardclientCVV': string;*/
    'sCreditcardclientCVV': string;
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
 * A CreditcardclientRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardclientRequest
 */
export class DataObjectCreditcardclientRequest {
   pkiCreditcardclientID?:number = undefined
   fksCreditcardtokenID?:string = undefined
   bCreditcardclientrelationIsdefault:boolean = false
   sCreditcardclientDescription:string = ''
   bCreditcardclientAllowedcompanypayment:boolean = false
   bCreditcardclientAllowedezsign:boolean = false
   bCreditcardclientAllowedtranquillit:boolean = false
   objCreditcarddetail:CreditcarddetailRequest = new DataObjectCreditcarddetailRequest()
   sCreditcardclientCVV:string = ''
}

/**
 * @export 
 * A CreditcardclientRequest Validation Object
 * @class ValidationObjectCreditcardclientRequest
 */
export class ValidationObjectCreditcardclientRequest {
   pkiCreditcardclientID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fksCreditcardtokenID = {
      type: 'string',
      pattern: /^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$/,
      required: false
   }
   bCreditcardclientrelationIsdefault = {
      type: 'boolean',
      required: true
   }
   sCreditcardclientDescription = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: true
   }
   bCreditcardclientAllowedcompanypayment = {
      type: 'boolean',
      required: true
   }
   bCreditcardclientAllowedezsign = {
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
      pattern: /^[0-9]{3,4}$/,
      required: true
   }
} 


