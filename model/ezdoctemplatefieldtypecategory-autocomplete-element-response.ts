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
 * A Ezdoctemplatefieldtypecategory AutocompleteElement Response
 * @export
 * @interface EzdoctemplatefieldtypecategoryAutocompleteElementResponse
 */
export interface EzdoctemplatefieldtypecategoryAutocompleteElementResponse {
    /**
     * The unique ID of the Ezdoctemplatefieldtypecategory
     * @type {number}
     * @memberof EzdoctemplatefieldtypecategoryAutocompleteElementResponse
     */
    /*'pkiEzdoctemplatefieldtypecategoryID': number;*/
    'pkiEzdoctemplatefieldtypecategoryID': number;
    /**
     * The unique ID of the Ezdoctemplatetype
     * @type {number}
     * @memberof EzdoctemplatefieldtypecategoryAutocompleteElementResponse
     */
    /*'fkiEzdoctemplatetypeID': number;*/
    'fkiEzdoctemplatetypeID': number;
    /**
     * The description of the Ezdoctemplatefieldtypecategory in the language of the requester
     * @type {string}
     * @memberof EzdoctemplatefieldtypecategoryAutocompleteElementResponse
     */
    /*'sEzdoctemplatefieldtypecategoryDescriptionX': string;*/
    'sEzdoctemplatefieldtypecategoryDescriptionX': string;
    /**
     * Whether the Ezdoctemplatefieldtypecategory is active or not
     * @type {boolean}
     * @memberof EzdoctemplatefieldtypecategoryAutocompleteElementResponse
     */
    /*'bEzdoctemplatefieldtypecategoryIsactive': boolean;*/
    'bEzdoctemplatefieldtypecategoryIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzdoctemplatefieldtypecategoryAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzdoctemplatefieldtypecategoryAutocompleteElementResponse
 */
export class DataObjectEzdoctemplatefieldtypecategoryAutocompleteElementResponse {
   pkiEzdoctemplatefieldtypecategoryID:number = 0
   fkiEzdoctemplatetypeID:number = 0
   sEzdoctemplatefieldtypecategoryDescriptionX:string = ''
   bEzdoctemplatefieldtypecategoryIsactive:boolean = false
}

/**
 * @export 
 * A EzdoctemplatefieldtypecategoryAutocompleteElementResponse Validation Object
 * @class ValidationObjectEzdoctemplatefieldtypecategoryAutocompleteElementResponse
 */
export class ValidationObjectEzdoctemplatefieldtypecategoryAutocompleteElementResponse {
   pkiEzdoctemplatefieldtypecategoryID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   fkiEzdoctemplatetypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sEzdoctemplatefieldtypecategoryDescriptionX = {
      type: 'string',
      pattern: /^.{0,55}$/,
      required: true
   }
   bEzdoctemplatefieldtypecategoryIsactive = {
      type: 'boolean',
      required: true
   }
} 


