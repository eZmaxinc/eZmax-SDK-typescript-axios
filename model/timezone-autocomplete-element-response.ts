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
 * A Timezone AutocompleteElement Response
 * @export
 * @interface TimezoneAutocompleteElementResponse
 */
export interface TimezoneAutocompleteElementResponse {
    /**
     * The description of the Timezone
     * @type {string}
     * @memberof TimezoneAutocompleteElementResponse
     */
    'sTimezoneName': string;
    /**
     * The unique ID of the Timezone
     * @type {number}
     * @memberof TimezoneAutocompleteElementResponse
     */
    'pkiTimezoneID': number;
    /**
     * Whether the Timezone is active or not
     * @type {boolean}
     * @memberof TimezoneAutocompleteElementResponse
     */
    'bTimezoneIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A TimezoneAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectTimezoneAutocompleteElementResponse
 */
export class DataObjectTimezoneAutocompleteElementResponse {
   sTimezoneName:string = ''
   pkiTimezoneID:number = 0
   bTimezoneIsactive:boolean = false
}

/**
 * @export 
 * A TimezoneAutocompleteElementResponse Validation Object
 * @class ValidationObjectTimezoneAutocompleteElementResponse
 */
export class ValidationObjectTimezoneAutocompleteElementResponse {
   sTimezoneName = {
      type: 'string',
      required: true
   }
   pkiTimezoneID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bTimezoneIsactive = {
      type: 'boolean',
      required: true
   }
} 


