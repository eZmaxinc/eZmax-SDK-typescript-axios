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
import type { FieldECreditcardtypeCodename } from './field-ecreditcardtype-codename';

/**
 * Creditcardtype AutocompleteElement Response
 * @export
 * @interface CreditcardtypeAutocompleteElementResponse
 */
export interface CreditcardtypeAutocompleteElementResponse {
    /**
     * The name of the Creditcardtype
     * @type {string}
     * @memberof CreditcardtypeAutocompleteElementResponse
     */
    /*'sCreditcardtypeName': string;*/
    'sCreditcardtypeName': string;
    /**
     * The unique ID of the Creditcardtype
     * @type {number}
     * @memberof CreditcardtypeAutocompleteElementResponse
     */
    /*'pkiCreditcardtypeID': number;*/
    'pkiCreditcardtypeID': number;
    /**
     * 
     * @type {FieldECreditcardtypeCodename}
     * @memberof CreditcardtypeAutocompleteElementResponse
     */
    /*'eCreditcardtypeCodename': FieldECreditcardtypeCodename;*/
    'eCreditcardtypeCodename': FieldECreditcardtypeCodename;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CreditcardtypeAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardtypeAutocompleteElementResponse
 */
export class DataObjectCreditcardtypeAutocompleteElementResponse {
   sCreditcardtypeName:string = ''
   pkiCreditcardtypeID:number = 0
   eCreditcardtypeCodename:FieldECreditcardtypeCodename = 'Amex'
}

/**
 * @export 
 * A CreditcardtypeAutocompleteElementResponse Validation Object
 * @class ValidationObjectCreditcardtypeAutocompleteElementResponse
 */
export class ValidationObjectCreditcardtypeAutocompleteElementResponse {
   sCreditcardtypeName = {
      type: 'string',
      pattern: /^.{1,30}$/,
      required: true
   }
   pkiCreditcardtypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   eCreditcardtypeCodename = {
      type: 'enum',
      allowableValues: ['Amex','Mastercard','Visa'],
      required: true
   }
} 


