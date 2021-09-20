/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.47
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */





/**
 * A Word Position Object
 * @export
 * @interface WordPositionResponse
 */
export interface WordPositionResponse {
    /**
     * The page where the word occurence was found
     * @type {number}
     * @memberof WordPositionResponse
     */
    iPage?: number;
    /**
     * The X coordinate (Horizontal) where the Word occurence was found.  Coordinate is calculated at 100dpi (dot per inch).
     * @type {number}
     * @memberof WordPositionResponse
     */
    iX?: number;
    /**
     * The Y coordinate (Vertical) where the Word occurence was found.  Coordinate is calculated at 100dpi (dot per inch).
     * @type {number}
     * @memberof WordPositionResponse
     */
    iY?: number;
}