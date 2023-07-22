/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Company AutocompleteElement Response
 * @export
 * @interface CompanyAutocompleteElementResponse
 */
export interface CompanyAutocompleteElementResponse {
    /**
     * The unique ID of the Company
     * @type {number}
     * @memberof CompanyAutocompleteElementResponse
     */
    'pkiCompanyID': number;
    /**
     * The Name of the Company in the language of the requester
     * @type {string}
     * @memberof CompanyAutocompleteElementResponse
     */
    'sCompanyNameX': string;
    /**
     * Whether the Company is active or not
     * @type {boolean}
     * @memberof CompanyAutocompleteElementResponse
     */
    'bCompanyIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CompanyAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCompanyAutocompleteElementResponse
 */
export class DataObjectCompanyAutocompleteElementResponse {
   pkiCompanyID:number = 0
   sCompanyNameX:string = ''
   bCompanyIsactive:boolean = false
}

/**
 * @export 
 * A CompanyAutocompleteElementResponse Validation Object
 * @class ValidationObjectCompanyAutocompleteElementResponse
 */
export class ValidationObjectCompanyAutocompleteElementResponse {
   pkiCompanyID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   sCompanyNameX = {
      type: 'string',
      required: true
   }
   bCompanyIsactive = {
      type: 'boolean',
      required: true
   }
} 


