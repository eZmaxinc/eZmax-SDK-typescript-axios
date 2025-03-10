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
 * Request for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/getWordsPositions
 * @export
 * @interface EzsigndocumentGetWordsPositionsV1Request
 */
export interface EzsigndocumentGetWordsPositionsV1Request {
    /**
     * Specify if you want to retrieve *All* words or specific *Words* from the document. If you specify *Words*, you must send the list of words to search for in *a_sWord*.
     * @type {string}
     * @memberof EzsigndocumentGetWordsPositionsV1Request
     */
    /*'eGet': EzsigndocumentGetWordsPositionsV1RequestEGetEnum;*/
    'eGet': EzsigndocumentGetWordsPositionsV1RequestEGetEnum;
    /**
     * IF *true*, words will be searched case-sensitive and results will be returned case-sensitive. IF *false*, words will be searched case-insensitive and results will be returned case-insensitive.
     * @type {boolean}
     * @memberof EzsigndocumentGetWordsPositionsV1Request
     */
    /*'bWordCaseSensitive': boolean;*/
    'bWordCaseSensitive': boolean;
    /**
     * Array of words to find in the document
     * @type {Array<string>}
     * @memberof EzsigndocumentGetWordsPositionsV1Request
     */
    /*'a_sWord'?: Array<string>;*/
    'a_sWord'?: Array<string>;
}

export const EzsigndocumentGetWordsPositionsV1RequestEGetEnum = {
    All: 'All',
    Words: 'Words'
} as const;
export type EzsigndocumentGetWordsPositionsV1RequestEGetEnum = typeof EzsigndocumentGetWordsPositionsV1RequestEGetEnum[keyof typeof EzsigndocumentGetWordsPositionsV1RequestEGetEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentGetWordsPositionsV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetWordsPositionsV1Request
 */
export class DataObjectEzsigndocumentGetWordsPositionsV1Request {
   eGet:EzsigndocumentGetWordsPositionsV1RequestEGetEnum = 'All'
   bWordCaseSensitive:boolean = false
   a_sWord?:Array<string> = undefined
}

/**
 * @export 
 * A EzsigndocumentGetWordsPositionsV1Request Validation Object
 * @class ValidationObjectEzsigndocumentGetWordsPositionsV1Request
 */
export class ValidationObjectEzsigndocumentGetWordsPositionsV1Request {
   eGet = {
      type: 'string',
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


