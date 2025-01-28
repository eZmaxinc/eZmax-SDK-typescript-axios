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



/**
 * A Creditcardmerchant List Element
 * @export
 * @interface CreditcardmerchantListElement
 */
export interface CreditcardmerchantListElement {
    /**
     * The unique ID of the Creditcardmerchant
     * @type {number}
     * @memberof CreditcardmerchantListElement
     */
    /*'pkiCreditcardmerchantID': number;*/
    'pkiCreditcardmerchantID': number;
    /**
     * The unique ID of the Bankaccount
     * @type {number}
     * @memberof CreditcardmerchantListElement
     */
    /*'fkiBankaccountID': number;*/
    'fkiBankaccountID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof CreditcardmerchantListElement
     */
    /*'fkiLanguageID'?: number;*/
    'fkiLanguageID'?: number;
    /**
     * Whether if visa are denied
     * @type {boolean}
     * @memberof CreditcardmerchantListElement
     */
    /*'bCreditcardmerchantDenyvisa': boolean;*/
    'bCreditcardmerchantDenyvisa': boolean;
    /**
     * Whether if mastercard are denied
     * @type {boolean}
     * @memberof CreditcardmerchantListElement
     */
    /*'bCreditcardmerchantDenymastercard': boolean;*/
    'bCreditcardmerchantDenymastercard': boolean;
    /**
     * Whether if amex are denied
     * @type {boolean}
     * @memberof CreditcardmerchantListElement
     */
    /*'bCreditcardmerchantDenyamex': boolean;*/
    'bCreditcardmerchantDenyamex': boolean;
    /**
     * Whether the creditcardmerchant is active or not
     * @type {boolean}
     * @memberof CreditcardmerchantListElement
     */
    /*'bCreditcardmerchantIsactive': boolean;*/
    'bCreditcardmerchantIsactive': boolean;
    /**
     * The description of the Creditcardmerchant
     * @type {string}
     * @memberof CreditcardmerchantListElement
     */
    /*'sCreditcardmerchantDescription': string;*/
    'sCreditcardmerchantDescription': string;
    /**
     * The storeid of the Creditcardmerchant
     * @type {string}
     * @memberof CreditcardmerchantListElement
     */
    /*'sCreditcardmerchantStoreid': string;*/
    'sCreditcardmerchantStoreid': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CreditcardmerchantListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardmerchantListElement
 */
export class DataObjectCreditcardmerchantListElement {
   pkiCreditcardmerchantID:number = 0
   fkiBankaccountID:number = 0
   fkiLanguageID?:number = undefined
   bCreditcardmerchantDenyvisa:boolean = false
   bCreditcardmerchantDenymastercard:boolean = false
   bCreditcardmerchantDenyamex:boolean = false
   bCreditcardmerchantIsactive:boolean = false
   sCreditcardmerchantDescription:string = ''
   sCreditcardmerchantStoreid:string = ''
}

/**
 * @export 
 * A CreditcardmerchantListElement Validation Object
 * @class ValidationObjectCreditcardmerchantListElement
 */
export class ValidationObjectCreditcardmerchantListElement {
   pkiCreditcardmerchantID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   fkiBankaccountID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: false
   }
   bCreditcardmerchantDenyvisa = {
      type: 'boolean',
      required: true
   }
   bCreditcardmerchantDenymastercard = {
      type: 'boolean',
      required: true
   }
   bCreditcardmerchantDenyamex = {
      type: 'boolean',
      required: true
   }
   bCreditcardmerchantIsactive = {
      type: 'boolean',
      required: true
   }
   sCreditcardmerchantDescription = {
      type: 'string',
      pattern: /^.{0,25}$/,
      required: true
   }
   sCreditcardmerchantStoreid = {
      type: 'string',
      pattern: /^.{0,25}$/,
      required: true
   }
} 


