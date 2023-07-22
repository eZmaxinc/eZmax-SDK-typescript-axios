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
 * A Ezsigntemplatepackagesigner Object
 * @export
 * @interface EzsigntemplatepackagesignerResponse
 */
export interface EzsigntemplatepackagesignerResponse {
    /**
     * The unique ID of the Ezsigntemplatepackagesigner
     * @type {number}
     * @memberof EzsigntemplatepackagesignerResponse
     */
    'pkiEzsigntemplatepackagesignerID': number;
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackagesignerResponse
     */
    'fkiEzsigntemplatepackageID': number;
    /**
     * The description of the Ezsigntemplatepackagesigner
     * @type {string}
     * @memberof EzsigntemplatepackagesignerResponse
     */
    'sEzsigntemplatepackagesignerDescription': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagesignerResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignerResponse
 */
export class DataObjectEzsigntemplatepackagesignerResponse {
   pkiEzsigntemplatepackagesignerID:number = 0
   fkiEzsigntemplatepackageID:number = 0
   sEzsigntemplatepackagesignerDescription:string = ''
}

/**
 * @export 
 * A EzsigntemplatepackagesignerResponse Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignerResponse
 */
export class ValidationObjectEzsigntemplatepackagesignerResponse {
   pkiEzsigntemplatepackagesignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsigntemplatepackagesignerDescription = {
      type: 'string',
      required: true
   }
} 


