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
 * A Franchisebroker AutocompleteElement Response
 * @export
 * @interface FranchisebrokerAutocompleteElementResponse
 */
export interface FranchisebrokerAutocompleteElementResponse {
    /**
     * The name of the Franchisebroker in the language of the requester
     * @type {string}
     * @memberof FranchisebrokerAutocompleteElementResponse
     */
    /*'sFranchisebrokerName': string;*/
    'sFranchisebrokerName': string;
    /**
     * The unique ID of the Franchisebroker
     * @type {number}
     * @memberof FranchisebrokerAutocompleteElementResponse
     */
    /*'pkiFranchisebrokerID': number;*/
    'pkiFranchisebrokerID': number;
    /**
     * Whether the Franchisebroker is active or not
     * @type {boolean}
     * @memberof FranchisebrokerAutocompleteElementResponse
     */
    /*'bFranchisebrokerIsactive': boolean;*/
    'bFranchisebrokerIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A FranchisebrokerAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectFranchisebrokerAutocompleteElementResponse
 */
export class DataObjectFranchisebrokerAutocompleteElementResponse {
   sFranchisebrokerName:string = ''
   pkiFranchisebrokerID:number = 0
   bFranchisebrokerIsactive:boolean = false
}

/**
 * @export 
 * A FranchisebrokerAutocompleteElementResponse Validation Object
 * @class ValidationObjectFranchisebrokerAutocompleteElementResponse
 */
export class ValidationObjectFranchisebrokerAutocompleteElementResponse {
   sFranchisebrokerName = {
      type: 'string',
      required: true
   }
   pkiFranchisebrokerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bFranchisebrokerIsactive = {
      type: 'boolean',
      required: true
   }
} 


