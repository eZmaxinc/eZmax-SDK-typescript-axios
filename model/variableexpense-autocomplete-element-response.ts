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
 * A Variableexpense AutocompleteElement Response
 * @export
 * @interface VariableexpenseAutocompleteElementResponse
 */
export interface VariableexpenseAutocompleteElementResponse {
    /**
     * The description of the Variableexpense in the language of the requester
     * @type {string}
     * @memberof VariableexpenseAutocompleteElementResponse
     */
    'sVariableexpenseDescriptionX': string;
    /**
     * The unique ID of the Variableexpense
     * @type {number}
     * @memberof VariableexpenseAutocompleteElementResponse
     */
    'pkiVariableexpenseID': number;
    /**
     * Whether the variableexpense is active or not
     * @type {boolean}
     * @memberof VariableexpenseAutocompleteElementResponse
     */
    'bVariableexpenseIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A VariableexpenseAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseAutocompleteElementResponse
 */
export class DataObjectVariableexpenseAutocompleteElementResponse {
   sVariableexpenseDescriptionX:string = ''
   pkiVariableexpenseID:number = 0
   bVariableexpenseIsactive:boolean = false
}

/**
 * @export 
 * A VariableexpenseAutocompleteElementResponse Validation Object
 * @class ValidationObjectVariableexpenseAutocompleteElementResponse
 */
export class ValidationObjectVariableexpenseAutocompleteElementResponse {
   sVariableexpenseDescriptionX = {
      type: 'string',
      pattern: '/^.{0,40}$/',
      required: true
   }
   pkiVariableexpenseID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   bVariableexpenseIsactive = {
      type: 'boolean',
      required: true
   }
} 


