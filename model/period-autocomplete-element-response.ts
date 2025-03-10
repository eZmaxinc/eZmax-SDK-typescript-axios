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



/**
 * A Period AutocompleteElement Response
 * @export
 * @interface PeriodAutocompleteElementResponse
 */
export interface PeriodAutocompleteElementResponse {
    /**
     * The YYYYMM of the Period
     * @type {string}
     * @memberof PeriodAutocompleteElementResponse
     */
    /*'sPeriodYYYYMM': string;*/
    'sPeriodYYYYMM': string;
    /**
     * The unique ID of the Period
     * @type {number}
     * @memberof PeriodAutocompleteElementResponse
     */
    /*'pkiPeriodID': number;*/
    'pkiPeriodID': number;
    /**
     * Whether the Period is active or not
     * @type {boolean}
     * @memberof PeriodAutocompleteElementResponse
     */
    /*'bPeriodIsactive': boolean;*/
    'bPeriodIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PeriodAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPeriodAutocompleteElementResponse
 */
export class DataObjectPeriodAutocompleteElementResponse {
   sPeriodYYYYMM:string = ''
   pkiPeriodID:number = 0
   bPeriodIsactive:boolean = false
}

/**
 * @export 
 * A PeriodAutocompleteElementResponse Validation Object
 * @class ValidationObjectPeriodAutocompleteElementResponse
 */
export class ValidationObjectPeriodAutocompleteElementResponse {
   sPeriodYYYYMM = {
      type: 'string',
      required: true
   }
   pkiPeriodID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bPeriodIsactive = {
      type: 'boolean',
      required: true
   }
} 


