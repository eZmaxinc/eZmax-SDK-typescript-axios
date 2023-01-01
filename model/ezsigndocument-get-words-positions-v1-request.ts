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



import { DefaultObject } from '../base'

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
    'eGet': EzsigndocumentGetWordsPositionsV1RequestEGetEnum;
    /**
     * IF *true*, words will be searched case-sensitive and results will be returned case-sensitive. IF *false*, words will be searched case-insensitive and results will be returned case-insensitive.
     * @type {boolean}
     * @memberof EzsigndocumentGetWordsPositionsV1Request
     */
    'bWordCaseSensitive': boolean;
    /**
     * Array of words to find in the document
     * @type {Array<string>}
     * @memberof EzsigndocumentGetWordsPositionsV1Request
     */
    'a_sWord'?: Array<string>;
}

export const EzsigndocumentGetWordsPositionsV1RequestEGetEnum = {
    All: 'All',
    Words: 'Words'
} as const;
export type EzsigndocumentGetWordsPositionsV1RequestEGetEnum = typeof EzsigndocumentGetWordsPositionsV1RequestEGetEnum[keyof typeof EzsigndocumentGetWordsPositionsV1RequestEGetEnum];


/**
 * A EzsigndocumentGetWordsPositionsV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentGetWordsPositionsV1Request
 */
export class DefaultObjectEzsigndocumentGetWordsPositionsV1Request extends DefaultObject {
   eGet:EzsigndocumentGetWordsPositionsV1RequestEGetEnum = 'All'
   bWordCaseSensitive:boolean = false
   a_sWord?:Array<string> = undefined
}


