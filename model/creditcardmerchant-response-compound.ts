/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CreditcardmerchantResponse } from './creditcardmerchant-response';

/**
 * @type CreditcardmerchantResponseCompound
 * A Creditcardmerchant Object
 * @export
 */
/*export type CreditcardmerchantResponseCompound = CreditcardmerchantResponse;*/
export interface CreditcardmerchantResponseCompound {
    /**
     * The unique ID of the Creditcardmerchant
     * @type {number}
     * @memberof CreditcardmerchantResponseCompound
     */
    pkiCreditcardmerchantID:number 
    /**
     * The unique ID of the Bankaccount
     * @type {number}
     * @memberof CreditcardmerchantResponseCompound
     */
    fkiBankaccountID:number 
    /**
     * The name of the bank
     * @type {string}
     * @memberof CreditcardmerchantResponseCompound
     */
    sBankaccountBankname?:string 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof CreditcardmerchantResponseCompound
     */
    fkiLanguageID?:number 
    /**
     * The Name of the Language in the language of the requester
     * @type {string}
     * @memberof CreditcardmerchantResponseCompound
     */
    sLanguageNameX?:string 
    /**
     * Whether if visa are denied
     * @type {boolean}
     * @memberof CreditcardmerchantResponseCompound
     */
    bCreditcardmerchantDenyvisa:boolean 
    /**
     * Whether if mastercard are denied
     * @type {boolean}
     * @memberof CreditcardmerchantResponseCompound
     */
    bCreditcardmerchantDenymastercard:boolean 
    /**
     * Whether if amex are denied
     * @type {boolean}
     * @memberof CreditcardmerchantResponseCompound
     */
    bCreditcardmerchantDenyamex:boolean 
    /**
     * Whether the creditcardmerchant is active or not
     * @type {boolean}
     * @memberof CreditcardmerchantResponseCompound
     */
    bCreditcardmerchantIsactive:boolean 
    /**
     * The description of the Creditcardmerchant
     * @type {string}
     * @memberof CreditcardmerchantResponseCompound
     */
    sCreditcardmerchantDescription:string 
    /**
     * The storeid of the Creditcardmerchant
     * @type {string}
     * @memberof CreditcardmerchantResponseCompound
     */
    sCreditcardmerchantStoreid:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CreditcardmerchantResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardmerchantResponseCompound
 */
export class DataObjectCreditcardmerchantResponseCompound {
    pkiCreditcardmerchantID:number = 0
    fkiBankaccountID:number = 0
    sBankaccountBankname?:string = undefined
    fkiLanguageID?:number = undefined
    sLanguageNameX?:string = undefined
    bCreditcardmerchantDenyvisa:boolean = false
    bCreditcardmerchantDenymastercard:boolean = false
    bCreditcardmerchantDenyamex:boolean = false
    bCreditcardmerchantIsactive:boolean = false
    sCreditcardmerchantDescription:string = ''
    sCreditcardmerchantStoreid:string = ''
}

/**
 * @export 
 * A CreditcardmerchantResponseCompound Validation Object
 * @class ValidationObjectCreditcardmerchantResponseCompound
 */
export class ValidationObjectCreditcardmerchantResponseCompound {
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
   sBankaccountBankname = {
      type: 'string',
      required: false
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: false
   }
   sLanguageNameX = {
      type: 'string',
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


