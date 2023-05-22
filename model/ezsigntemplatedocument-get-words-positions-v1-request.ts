/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Request for POST /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getWordsPositions
 * @export
 * @interface EzsigntemplatedocumentGetWordsPositionsV1Request
 */
export interface EzsigntemplatedocumentGetWordsPositionsV1Request {
    /**
     * Specify if you want to retrieve *All* words or specific *Words* from the document. If you specify *Words*, you must send the list of words to search for in *a_sWord*.
     * @type {string}
     * @memberof EzsigntemplatedocumentGetWordsPositionsV1Request
     */
    'eGet': EzsigntemplatedocumentGetWordsPositionsV1RequestEGetEnum;
    /**
     * IF *true*, words will be searched case-sensitive and results will be returned case-sensitive. IF *false*, words will be searched case-insensitive and results will be returned case-insensitive.
     * @type {boolean}
     * @memberof EzsigntemplatedocumentGetWordsPositionsV1Request
     */
    'bWordCaseSensitive': boolean;
    /**
     * Array of words to find in the document
     * @type {Array<string>}
     * @memberof EzsigntemplatedocumentGetWordsPositionsV1Request
     */
    'a_sWord'?: Array<string>;
}

export const EzsigntemplatedocumentGetWordsPositionsV1RequestEGetEnum = {
    All: 'All',
    Words: 'Words'
} as const;
export type EzsigntemplatedocumentGetWordsPositionsV1RequestEGetEnum = typeof EzsigntemplatedocumentGetWordsPositionsV1RequestEGetEnum[keyof typeof EzsigntemplatedocumentGetWordsPositionsV1RequestEGetEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentGetWordsPositionsV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentGetWordsPositionsV1Request
 */
export class DataObjectEzsigntemplatedocumentGetWordsPositionsV1Request {
   eGet:EzsigntemplatedocumentGetWordsPositionsV1RequestEGetEnum = 'All'
   bWordCaseSensitive:boolean = false
   a_sWord?:Array<string> = undefined
}

/**
 * @export 
 * A EzsigntemplatedocumentGetWordsPositionsV1Request Validation Object
 * @class ValidationObjectEzsigntemplatedocumentGetWordsPositionsV1Request
 */
export class ValidationObjectEzsigntemplatedocumentGetWordsPositionsV1Request {
   eGet = {
      type: 'enum',
      allowableValues: ['All','Words'],
      required: true
   }
   bWordCaseSensitive = {
      type: 'boolean',
      required: true
   }
   a_sWord = {
      type: 'array',
      required: false
   }
} 


