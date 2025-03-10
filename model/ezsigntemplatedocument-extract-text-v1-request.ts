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
 * Request for POST /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/extractText
 * @export
 * @interface EzsigntemplatedocumentExtractTextV1Request
 */
export interface EzsigntemplatedocumentExtractTextV1Request {
    /**
     * The page where the area is located
     * @type {number}
     * @memberof EzsigntemplatedocumentExtractTextV1Request
     */
    /*'iPage': number;*/
    'iPage': number;
    /**
     * The section of the page
     * @type {string}
     * @memberof EzsigntemplatedocumentExtractTextV1Request
     */
    /*'eSection'?: EzsigntemplatedocumentExtractTextV1RequestESectionEnum;*/
    'eSection'?: EzsigntemplatedocumentExtractTextV1RequestESectionEnum;
    /**
     * The X coordinate (Horizontal). Require when eSection = \'Region\' or eSection is not set.
     * @type {number}
     * @memberof EzsigntemplatedocumentExtractTextV1Request
     */
    /*'iX'?: number;*/
    'iX'?: number;
    /**
     * The Y coordinate (Vertical). Require when eSection = \'Region\' or eSection is not set.
     * @type {number}
     * @memberof EzsigntemplatedocumentExtractTextV1Request
     */
    /*'iY'?: number;*/
    'iY'?: number;
    /**
     * Area\'s width. Require when eSection = \'Region\' or eSection is not set.
     * @type {number}
     * @memberof EzsigntemplatedocumentExtractTextV1Request
     */
    /*'iWidth'?: number;*/
    'iWidth'?: number;
    /**
     * Area\'s height. Require when eSection = \'Region\' or eSection is not set.
     * @type {number}
     * @memberof EzsigntemplatedocumentExtractTextV1Request
     */
    /*'iHeight'?: number;*/
    'iHeight'?: number;
}

export const EzsigntemplatedocumentExtractTextV1RequestESectionEnum = {
    FirstLine: 'FirstLine',
    LastLine: 'LastLine',
    Region: 'Region'
} as const;
export type EzsigntemplatedocumentExtractTextV1RequestESectionEnum = typeof EzsigntemplatedocumentExtractTextV1RequestESectionEnum[keyof typeof EzsigntemplatedocumentExtractTextV1RequestESectionEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentExtractTextV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentExtractTextV1Request
 */
export class DataObjectEzsigntemplatedocumentExtractTextV1Request {
   iPage:number = 0
   eSection?:EzsigntemplatedocumentExtractTextV1RequestESectionEnum = undefined
   iX?:number = undefined
   iY?:number = undefined
   iWidth?:number = undefined
   iHeight?:number = undefined
}

/**
 * @export 
 * A EzsigntemplatedocumentExtractTextV1Request Validation Object
 * @class ValidationObjectEzsigntemplatedocumentExtractTextV1Request
 */
export class ValidationObjectEzsigntemplatedocumentExtractTextV1Request {
   iPage = {
      type: 'integer',
      required: true
   }
   eSection = {
      type: 'string',
      required: false
   }
   iX = {
      type: 'integer',
      required: false
   }
   iY = {
      type: 'integer',
      required: false
   }
   iWidth = {
      type: 'integer',
      required: false
   }
   iHeight = {
      type: 'integer',
      required: false
   }
} 


