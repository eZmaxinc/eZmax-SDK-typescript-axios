/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

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
    'iPage'?: number;
    /**
     * The X coordinate (Horizontal) where the Word occurence was found.  Coordinate is calculated at 100dpi (dot per inch).
     * @type {number}
     * @memberof CustomWordPositionOccurenceResponse
     */
    'iX'?: number;
    /**
     * The Y coordinate (Vertical) where the Word occurence was found.  Coordinate is calculated at 100dpi (dot per inch).
     * @type {number}
     * @memberof CustomWordPositionOccurenceResponse
     */
    'iY'?: number;
}
/**
 * A CustomWordPositionOccurenceResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomWordPositionOccurenceResponse
 */
export class DefaultObjectCustomWordPositionOccurenceResponse extends DefaultObject {
   iPage?:number = undefined
   iX?:number = undefined
   iY?:number = undefined
}


