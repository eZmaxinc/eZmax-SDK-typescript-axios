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
 * A Ezdoctemplatedocument AutocompleteElement Response
 * @export
 * @interface EzdoctemplatedocumentAutocompleteElementResponse
 */
export interface EzdoctemplatedocumentAutocompleteElementResponse {
    /**
     * The unique ID of the Ezdoctemplatedocument
     * @type {number}
     * @memberof EzdoctemplatedocumentAutocompleteElementResponse
     */
    /*'pkiEzdoctemplatedocumentID': number;*/
    'pkiEzdoctemplatedocumentID': number;
    /**
     * The name of the Ezdoctemplatedocument in the language of the requester
     * @type {string}
     * @memberof EzdoctemplatedocumentAutocompleteElementResponse
     */
    /*'sEzdoctemplatedocumentNameX': string;*/
    'sEzdoctemplatedocumentNameX': string;
    /**
     * Whether the ezdoctemplatedocument is active or not
     * @type {boolean}
     * @memberof EzdoctemplatedocumentAutocompleteElementResponse
     */
    /*'bEzdoctemplatedocumentIsactive': boolean;*/
    'bEzdoctemplatedocumentIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzdoctemplatedocumentAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzdoctemplatedocumentAutocompleteElementResponse
 */
export class DataObjectEzdoctemplatedocumentAutocompleteElementResponse {
   pkiEzdoctemplatedocumentID:number = 0
   sEzdoctemplatedocumentNameX:string = ''
   bEzdoctemplatedocumentIsactive:boolean = false
}

/**
 * @export 
 * A EzdoctemplatedocumentAutocompleteElementResponse Validation Object
 * @class ValidationObjectEzdoctemplatedocumentAutocompleteElementResponse
 */
export class ValidationObjectEzdoctemplatedocumentAutocompleteElementResponse {
   pkiEzdoctemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   sEzdoctemplatedocumentNameX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: true
   }
   bEzdoctemplatedocumentIsactive = {
      type: 'boolean',
      required: true
   }
} 


