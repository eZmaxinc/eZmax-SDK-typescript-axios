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


// May contain unused imports in some cases
// @ts-ignore
import { FranchisereferalincomeCreateObjectV1ResponseMPayload } from './franchisereferalincome-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface FranchisereferalincomeCreateObjectV1ResponseAllOf
 */
export interface FranchisereferalincomeCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {FranchisereferalincomeCreateObjectV1ResponseMPayload}
     * @memberof FranchisereferalincomeCreateObjectV1ResponseAllOf
     */
    'mPayload': FranchisereferalincomeCreateObjectV1ResponseMPayload;
}
/**
 * A FranchisereferalincomeCreateObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectFranchisereferalincomeCreateObjectV1ResponseAllOf
 */
export class DefaultObjectFranchisereferalincomeCreateObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<FranchisereferalincomeCreateObjectV1ResponseMPayload> = {}
}


