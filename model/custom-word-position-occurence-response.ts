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
 * A Word Position Object
 * @export
 * @interface CustomWordPositionOccurenceResponse
 */
export interface CustomWordPositionOccurenceResponse {
    /**
     * The page where the word occurence was found
     * @type {number}
     * @memberof CustomWordPositionOccurenceResponse
     */
    /*'iPage'?: number;*/
    'iPage'?: number;
    /**
     * The X coordinate (Horizontal) where the Word occurence was found.  Coordinate is calculated at 100dpi (dot per inch).
     * @type {number}
     * @memberof CustomWordPositionOccurenceResponse
     */
    /*'iX'?: number;*/
    'iX'?: number;
    /**
     * The Y coordinate (Vertical) where the Word occurence was found.  Coordinate is calculated at 100dpi (dot per inch).
     * @type {number}
     * @memberof CustomWordPositionOccurenceResponse
     */
    /*'iY'?: number;*/
    'iY'?: number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomWordPositionOccurenceResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomWordPositionOccurenceResponse
 */
export class DataObjectCustomWordPositionOccurenceResponse {
   iPage?:number = undefined
   iX?:number = undefined
   iY?:number = undefined
}

/**
 * @export 
 * A CustomWordPositionOccurenceResponse Validation Object
 * @class ValidationObjectCustomWordPositionOccurenceResponse
 */
export class ValidationObjectCustomWordPositionOccurenceResponse {
   iPage = {
      type: 'integer',
      minimum: 1,
      required: false
   }
   iX = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iY = {
      type: 'integer',
      minimum: 0,
      required: false
   }
} 


