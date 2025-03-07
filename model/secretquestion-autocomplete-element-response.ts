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
 * A Secretquestion AutocompleteElement Response
 * @export
 * @interface SecretquestionAutocompleteElementResponse
 */
export interface SecretquestionAutocompleteElementResponse {
    /**
     * The text of the Secretquestion in the language of the requester
     * @type {string}
     * @memberof SecretquestionAutocompleteElementResponse
     */
    /*'sSecretquestionTextX': string;*/
    'sSecretquestionTextX': string;
    /**
     * The unique ID of the Secretquestion.  Valid values:  |Value|Description| |-|-| |1|The name of the hospital in which you were born| |2|The name of your grade school| |3|The last name of your favorite teacher| |4|Your favorite sports team| |5|Your favorite TV show| |6|Your favorite movie| |7|The name of the street on which you grew up| |8|The name of your first employer| |9|Your first car| |10|Your favorite food| |11|The name of your first pet| |12|Favorite musician/band| |13|What instrument you play| |14|Your father\'s middle name| |15|Your mother\'s maiden name| |16|Name of your eldest child| |17|Your spouse\'s middle name| |18|Favorite restaurant| |19|Childhood nickname| |20|Favorite vacation destination| |21|Your boat\'s name| |22|Date of Birth (YYYY-MM-DD)| |22|Secret Code| |22|Your reference code|
     * @type {number}
     * @memberof SecretquestionAutocompleteElementResponse
     */
    /*'pkiSecretquestionID': number;*/
    'pkiSecretquestionID': number;
    /**
     * Whether the Secretquestion is active or not
     * @type {boolean}
     * @memberof SecretquestionAutocompleteElementResponse
     */
    /*'bSecretquestionIsactive': boolean;*/
    'bSecretquestionIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A SecretquestionAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSecretquestionAutocompleteElementResponse
 */
export class DataObjectSecretquestionAutocompleteElementResponse {
   sSecretquestionTextX:string = ''
   pkiSecretquestionID:number = 0
   bSecretquestionIsactive:boolean = false
}

/**
 * @export 
 * A SecretquestionAutocompleteElementResponse Validation Object
 * @class ValidationObjectSecretquestionAutocompleteElementResponse
 */
export class ValidationObjectSecretquestionAutocompleteElementResponse {
   sSecretquestionTextX = {
      type: 'string',
      required: true
   }
   pkiSecretquestionID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bSecretquestionIsactive = {
      type: 'boolean',
      required: true
   }
} 


