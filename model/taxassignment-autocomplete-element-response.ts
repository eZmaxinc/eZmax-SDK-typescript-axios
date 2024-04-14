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
 * A Taxassignment AutocompleteElement Response
 * @export
 * @interface TaxassignmentAutocompleteElementResponse
 */
export interface TaxassignmentAutocompleteElementResponse {
    /**
     * The description of the Taxassignment  in the language of the requester
     * @type {string}
     * @memberof TaxassignmentAutocompleteElementResponse
     */
    /*'sTaxassignmentDescriptionX': string;*/
    'sTaxassignmentDescriptionX': string;
    /**
     * The unique ID of the Taxassignment.  Valid values:  |Value|Description| |-|-| |1|No tax| |2|GST| |3|HST (ON)| |4|HST (NB)| |5|HST (NS)| |6|HST (NL)| |7|HST (PE)| |8|GST + QST (QC)| |9|GST + QST (QC) Non-Recoverable| |10|GST + PST (BC)| |11|GST + PST (SK)| |12|GST + RST (MB)| |13|GST + PST (BC) Non-Recoverable| |14|GST + PST (SK) Non-Recoverable| |15|GST + RST (MB) Non-Recoverable|
     * @type {number}
     * @memberof TaxassignmentAutocompleteElementResponse
     */
    /*'pkiTaxassignmentID': number;*/
    'pkiTaxassignmentID': number;
    /**
     * Whether the Taxassignment is active or not
     * @type {boolean}
     * @memberof TaxassignmentAutocompleteElementResponse
     */
    /*'bTaxassignmentIsactive': boolean;*/
    'bTaxassignmentIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A TaxassignmentAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectTaxassignmentAutocompleteElementResponse
 */
export class DataObjectTaxassignmentAutocompleteElementResponse {
   sTaxassignmentDescriptionX:string = ''
   pkiTaxassignmentID:number = 0
   bTaxassignmentIsactive:boolean = false
}

/**
 * @export 
 * A TaxassignmentAutocompleteElementResponse Validation Object
 * @class ValidationObjectTaxassignmentAutocompleteElementResponse
 */
export class ValidationObjectTaxassignmentAutocompleteElementResponse {
   sTaxassignmentDescriptionX = {
      type: 'string',
      required: true
   }
   pkiTaxassignmentID = {
      type: 'integer',
      minimum: 0,
      maximum: 15,
      required: true
   }
   bTaxassignmentIsactive = {
      type: 'boolean',
      required: true
   }
} 


