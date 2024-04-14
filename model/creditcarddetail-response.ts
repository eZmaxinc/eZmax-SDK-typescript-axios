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



/**
 * A Creditcarddetail Object
 * @export
 * @interface CreditcarddetailResponse
 */
export interface CreditcarddetailResponse {
    /**
     * The unique ID of the Creditcarddetail
     * @type {number}
     * @memberof CreditcarddetailResponse
     */
    /*'pkiCreditcarddetailID': number;*/
    'pkiCreditcarddetailID': number;
    /**
     * The unique ID of the Creditcardtype
     * @type {number}
     * @memberof CreditcarddetailResponse
     */
    /*'fkiCreditcardtypeID': number;*/
    'fkiCreditcardtypeID': number;
    /**
     * The numbermasked of the Creditcarddetail
     * @type {string}
     * @memberof CreditcarddetailResponse
     */
    /*'sCreditcarddetailNumbermasked': string;*/
    'sCreditcarddetailNumbermasked': string;
    /**
     * The expirationmonth of the Creditcarddetail
     * @type {number}
     * @memberof CreditcarddetailResponse
     */
    /*'iCreditcarddetailExpirationmonth': number;*/
    'iCreditcarddetailExpirationmonth': number;
    /**
     * The expirationyear of the Creditcarddetail
     * @type {number}
     * @memberof CreditcarddetailResponse
     */
    /*'iCreditcarddetailExpirationyear': number;*/
    'iCreditcarddetailExpirationyear': number;
    /**
     * The civic of the Creditcarddetail
     * @type {string}
     * @memberof CreditcarddetailResponse
     */
    /*'sCreditcarddetailCivic': string;*/
    'sCreditcarddetailCivic': string;
    /**
     * The street of the Creditcarddetail
     * @type {string}
     * @memberof CreditcarddetailResponse
     */
    /*'sCreditcarddetailStreet': string;*/
    'sCreditcarddetailStreet': string;
    /**
     * The zip of the Creditcarddetail
     * @type {string}
     * @memberof CreditcarddetailResponse
     */
    /*'sCreditcarddetailZip': string;*/
    'sCreditcarddetailZip': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CreditcarddetailResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcarddetailResponse
 */
export class DataObjectCreditcarddetailResponse {
   pkiCreditcarddetailID:number = 0
   fkiCreditcardtypeID:number = 0
   sCreditcarddetailNumbermasked:string = ''
   iCreditcarddetailExpirationmonth:number = 0
   iCreditcarddetailExpirationyear:number = 0
   sCreditcarddetailCivic:string = ''
   sCreditcarddetailStreet:string = ''
   sCreditcarddetailZip:string = ''
}

/**
 * @export 
 * A CreditcarddetailResponse Validation Object
 * @class ValidationObjectCreditcarddetailResponse
 */
export class ValidationObjectCreditcarddetailResponse {
   pkiCreditcarddetailID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiCreditcardtypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sCreditcarddetailNumbermasked = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: true
   }
   iCreditcarddetailExpirationmonth = {
      type: 'integer',
      minimum: 0,
      maximum: 12,
      required: true
   }
   iCreditcarddetailExpirationyear = {
      type: 'integer',
      minimum: 0,
      maximum: 2200,
      required: true
   }
   sCreditcarddetailCivic = {
      type: 'string',
      pattern: '/^.{0,8}$/',
      required: true
   }
   sCreditcarddetailStreet = {
      type: 'string',
      pattern: '/^.{0,40}$/',
      required: true
   }
   sCreditcarddetailZip = {
      type: 'string',
      pattern: '/^.{0,10}$/',
      required: true
   }
} 


